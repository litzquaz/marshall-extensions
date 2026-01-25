/**
 * Marshall Extension Communication Layer
 * Secure message passing between extensions and sandbox
 * Part of the NullSec Security Suite
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import * as net from 'net';

// Message types for extension <-> sandbox communication
export enum MessageType {
    // Requests
    API_REQUEST = 'api_request',
    PERMISSION_REQUEST = 'permission_request',
    STORAGE_REQUEST = 'storage_request',
    
    // Responses
    API_RESPONSE = 'api_response',
    PERMISSION_RESPONSE = 'permission_response',
    STORAGE_RESPONSE = 'storage_response',
    
    // Alerts
    THREAT_ALERT = 'threat_alert',
    STATUS_UPDATE = 'status_update',
    
    // Control
    HANDSHAKE = 'handshake',
    HEARTBEAT = 'heartbeat',
    TERMINATE = 'terminate',
}

export interface Message {
    id: string;
    type: MessageType;
    timestamp: number;
    extensionId: string;
    payload: any;
    signature?: string;
}

export interface EncryptedMessage {
    iv: string;
    data: string;
    tag: string;
}

// Security configuration
export interface SecurityConfig {
    encryptionAlgorithm: 'aes-256-gcm' | 'chacha20-poly1305';
    keyDerivation: 'pbkdf2' | 'hkdf';
    signatureAlgorithm: 'ed25519' | 'hmac-sha256';
    messageTimeout: number;
    maxMessageSize: number;
    replayWindow: number;
}

const DEFAULT_CONFIG: SecurityConfig = {
    encryptionAlgorithm: 'aes-256-gcm',
    keyDerivation: 'hkdf',
    signatureAlgorithm: 'hmac-sha256',
    messageTimeout: 30000,
    maxMessageSize: 1024 * 1024, // 1MB
    replayWindow: 60000, // 1 minute
};

/**
 * Secure communication channel between extension and sandbox
 */
export class SecureChannel extends EventEmitter {
    private sessionKey: Buffer | null = null;
    private extensionId: string;
    private config: SecurityConfig;
    private messageCounter: bigint = 0n;
    private seenNonces: Set<string> = new Set();
    private socket: net.Socket | null = null;
    private connected: boolean = false;
    private pendingRequests: Map<string, {
        resolve: (value: any) => void;
        reject: (error: Error) => void;
        timeout: NodeJS.Timeout;
    }> = new Map();

    constructor(extensionId: string, config: Partial<SecurityConfig> = {}) {
        super();
        this.extensionId = extensionId;
        this.config = { ...DEFAULT_CONFIG, ...config };
    }

    /**
     * Connect to sandbox daemon
     */
    async connect(socketPath: string): Promise<void> {
        return new Promise((resolve, reject) => {
            this.socket = net.createConnection(socketPath, () => {
                this.connected = true;
                this.performHandshake()
                    .then(resolve)
                    .catch(reject);
            });

            this.socket.on('data', (data) => this.handleData(data));
            this.socket.on('error', (err) => {
                this.emit('error', err);
                reject(err);
            });
            this.socket.on('close', () => {
                this.connected = false;
                this.emit('disconnected');
            });
        });
    }

    /**
     * Perform key exchange handshake
     */
    private async performHandshake(): Promise<void> {
        // Generate ephemeral key pair for ECDH
        const ecdh = crypto.createECDH('prime256v1');
        const publicKey = ecdh.generateKeys();

        // Send handshake
        const handshake: Message = {
            id: this.generateMessageId(),
            type: MessageType.HANDSHAKE,
            timestamp: Date.now(),
            extensionId: this.extensionId,
            payload: {
                publicKey: publicKey.toString('base64'),
                protocols: ['v1'],
            },
        };

        const response = await this.sendAndWait(handshake);
        
        // Derive session key from shared secret
        const sharedSecret = ecdh.computeSecret(
            Buffer.from(response.payload.publicKey, 'base64')
        );
        
        this.sessionKey = this.deriveKey(sharedSecret);
        this.emit('connected');
    }

    /**
     * Derive encryption key using HKDF
     */
    private deriveKey(sharedSecret: Buffer): Buffer {
        const salt = Buffer.from('marshall-sandbox-v1');
        const info = Buffer.from(`session:${this.extensionId}`);
        
        return crypto.hkdfSync(
            'sha256',
            sharedSecret,
            salt,
            info,
            32
        );
    }

    /**
     * Encrypt a message
     */
    private encrypt(plaintext: string): EncryptedMessage {
        if (!this.sessionKey) {
            throw new Error('Session not established');
        }

        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(
            this.config.encryptionAlgorithm,
            this.sessionKey,
            iv,
            { authTagLength: 16 }
        );

        let encrypted = cipher.update(plaintext, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        
        const tag = (cipher as any).getAuthTag();

        return {
            iv: iv.toString('base64'),
            data: encrypted,
            tag: tag.toString('base64'),
        };
    }

    /**
     * Decrypt a message
     */
    private decrypt(encrypted: EncryptedMessage): string {
        if (!this.sessionKey) {
            throw new Error('Session not established');
        }

        const iv = Buffer.from(encrypted.iv, 'base64');
        const tag = Buffer.from(encrypted.tag, 'base64');
        
        const decipher = crypto.createDecipheriv(
            this.config.encryptionAlgorithm,
            this.sessionKey,
            iv,
            { authTagLength: 16 }
        );
        
        (decipher as any).setAuthTag(tag);

        let decrypted = decipher.update(encrypted.data, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    }

    /**
     * Sign a message
     */
    private sign(message: Message): string {
        if (!this.sessionKey) {
            throw new Error('Session not established');
        }

        const hmac = crypto.createHmac('sha256', this.sessionKey);
        hmac.update(JSON.stringify({
            id: message.id,
            type: message.type,
            timestamp: message.timestamp,
            extensionId: message.extensionId,
        }));
        
        return hmac.digest('base64');
    }

    /**
     * Verify message signature and prevent replay
     */
    private verify(message: Message): boolean {
        // Check timestamp (prevent replay)
        const age = Date.now() - message.timestamp;
        if (age > this.config.replayWindow || age < -this.config.replayWindow) {
            return false;
        }

        // Check nonce (prevent replay)
        if (this.seenNonces.has(message.id)) {
            return false;
        }
        this.seenNonces.add(message.id);

        // Verify signature
        const expectedSig = this.sign(message);
        return message.signature === expectedSig;
    }

    /**
     * Generate unique message ID
     */
    private generateMessageId(): string {
        this.messageCounter++;
        const random = crypto.randomBytes(8).toString('hex');
        return `${this.extensionId}-${this.messageCounter}-${random}`;
    }

    /**
     * Send message and wait for response
     */
    private sendAndWait(message: Message): Promise<Message> {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                this.pendingRequests.delete(message.id);
                reject(new Error('Request timeout'));
            }, this.config.messageTimeout);

            this.pendingRequests.set(message.id, { resolve, reject, timeout });
            this.send(message);
        });
    }

    /**
     * Send a message through the channel
     */
    private send(message: Message): void {
        if (!this.socket || !this.connected) {
            throw new Error('Not connected');
        }

        // Sign if we have a session
        if (this.sessionKey) {
            message.signature = this.sign(message);
        }

        let data: string;
        if (this.sessionKey && message.type !== MessageType.HANDSHAKE) {
            // Encrypt
            const encrypted = this.encrypt(JSON.stringify(message));
            data = JSON.stringify({ encrypted: true, ...encrypted });
        } else {
            data = JSON.stringify(message);
        }

        // Send with length prefix
        const length = Buffer.alloc(4);
        length.writeUInt32BE(data.length);
        this.socket.write(Buffer.concat([length, Buffer.from(data)]));
    }

    /**
     * Handle incoming data
     */
    private handleData(data: Buffer): void {
        try {
            // Parse length-prefixed message
            const length = data.readUInt32BE(0);
            const jsonData = data.slice(4, 4 + length).toString();
            const parsed = JSON.parse(jsonData);

            let message: Message;
            if (parsed.encrypted) {
                const decrypted = this.decrypt(parsed);
                message = JSON.parse(decrypted);
            } else {
                message = parsed;
            }

            // Handle response to pending request
            const pending = this.pendingRequests.get(message.id);
            if (pending) {
                clearTimeout(pending.timeout);
                this.pendingRequests.delete(message.id);
                pending.resolve(message);
                return;
            }

            // Emit for other handlers
            this.emit('message', message);
            this.emit(message.type, message);

        } catch (err) {
            this.emit('error', err);
        }
    }

    /**
     * Make an API request through sandbox
     */
    async apiRequest(api: string, args: any): Promise<any> {
        const message: Message = {
            id: this.generateMessageId(),
            type: MessageType.API_REQUEST,
            timestamp: Date.now(),
            extensionId: this.extensionId,
            payload: { api, args },
        };

        const response = await this.sendAndWait(message);
        
        if (!response.payload.success) {
            throw new Error(response.payload.error || 'API request failed');
        }

        return response.payload.data;
    }

    /**
     * Request a permission
     */
    async requestPermission(permission: string): Promise<boolean> {
        const message: Message = {
            id: this.generateMessageId(),
            type: MessageType.PERMISSION_REQUEST,
            timestamp: Date.now(),
            extensionId: this.extensionId,
            payload: { permission },
        };

        const response = await this.sendAndWait(message);
        return response.payload.granted === true;
    }

    /**
     * Report a threat to sandbox
     */
    reportThreat(threatType: string, details: any): void {
        const message: Message = {
            id: this.generateMessageId(),
            type: MessageType.THREAT_ALERT,
            timestamp: Date.now(),
            extensionId: this.extensionId,
            payload: { threatType, details },
        };

        this.send(message);
    }

    /**
     * Disconnect from sandbox
     */
    disconnect(): void {
        if (this.socket) {
            this.socket.end();
            this.socket = null;
        }
        this.connected = false;
        this.sessionKey = null;
        this.pendingRequests.clear();
    }
}

/**
 * Extension API proxy that routes all calls through sandbox
 */
export class SandboxedAPI {
    private channel: SecureChannel;

    constructor(channel: SecureChannel) {
        this.channel = channel;
    }

    // Tab API
    async getCurrentTab(): Promise<any> {
        return this.channel.apiRequest('tabs.getCurrent', {});
    }

    async createTab(options: any): Promise<any> {
        return this.channel.apiRequest('tabs.create', options);
    }

    // Storage API
    async storageGet(key: string): Promise<any> {
        return this.channel.apiRequest('storage.get', { key });
    }

    async storageSet(key: string, value: any): Promise<void> {
        return this.channel.apiRequest('storage.set', { key, value });
    }

    // Network API
    async fetch(url: string, options?: any): Promise<any> {
        return this.channel.apiRequest('network.fetch', { url, options });
    }

    // DOM API
    async querySelector(selector: string): Promise<any> {
        return this.channel.apiRequest('dom.querySelector', { selector });
    }

    async querySelectorAll(selector: string): Promise<any[]> {
        return this.channel.apiRequest('dom.querySelectorAll', { selector });
    }

    // UI API
    showPanel(html: string, options?: any): void {
        this.channel.apiRequest('ui.showPanel', { html, options });
    }

    notify(message: string, type: string = 'info'): void {
        this.channel.apiRequest('ui.notify', { message, type });
    }

    // Clipboard API
    async clipboardRead(): Promise<string> {
        return this.channel.apiRequest('clipboard.read', {});
    }

    async clipboardWrite(text: string): Promise<void> {
        return this.channel.apiRequest('clipboard.write', { text });
    }
}

// Export factory function
export function createSecureAPI(extensionId: string, socketPath: string): Promise<SandboxedAPI> {
    const channel = new SecureChannel(extensionId);
    return channel.connect(socketPath).then(() => new SandboxedAPI(channel));
}
