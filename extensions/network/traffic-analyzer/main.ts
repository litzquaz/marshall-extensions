/**
 * Traffic Analyzer Extension for Marshall Browser
 * Real-time network traffic analysis and anomaly detection
 * Part of Marshall Extensions Collection
 */

import { createSecureAPI, SandboxedAPI } from '../../../sandbox/comm/channel';

interface RequestLog {
    id: string;
    timestamp: number;
    method: string;
    url: string;
    type: string;
    status: number;
    size: number;
    duration: number;
    initiator: string;
    headers: Record<string, string>;
    responseHeaders: Record<string, string>;
    blocked: boolean;
    reason?: string;
}

interface TrafficStats {
    totalRequests: number;
    blockedRequests: number;
    totalBytes: number;
    byType: Record<string, number>;
    byDomain: Record<string, number>;
    byMethod: Record<string, number>;
}

interface AnomalyRule {
    id: string;
    name: string;
    pattern: RegExp | string;
    action: 'block' | 'alert' | 'log';
    severity: 'low' | 'medium' | 'high' | 'critical';
}

class TrafficAnalyzer {
    private api: SandboxedAPI | null = null;
    private requests: Map<string, RequestLog> = new Map();
    private stats: TrafficStats;
    private anomalyRules: AnomalyRule[] = [];
    private blocklist: Set<string> = new Set();
    private maxLogs: number = 5000;

    constructor() {
        this.stats = this.initStats();
        this.loadDefaultRules();
    }

    private initStats(): TrafficStats {
        return {
            totalRequests: 0,
            blockedRequests: 0,
            totalBytes: 0,
            byType: {},
            byDomain: {},
            byMethod: {},
        };
    }

    private loadDefaultRules(): void {
        this.anomalyRules = [
            // Cryptocurrency mining
            {
                id: 'crypto-miner',
                name: 'Cryptocurrency Mining',
                pattern: /coinhive|cryptonight|minero|webminer/i,
                action: 'block',
                severity: 'high',
            },
            // Tracking pixels
            {
                id: 'tracking-pixel',
                name: 'Tracking Pixel',
                pattern: /pixel\.gif|beacon\.gif|track\.gif|1x1\.(gif|png)/i,
                action: 'log',
                severity: 'low',
            },
            // Known malware domains
            {
                id: 'malware-domain',
                name: 'Known Malware Domain',
                pattern: /malware|botnet|ransomware/i,
                action: 'block',
                severity: 'critical',
            },
            // Data exfiltration patterns
            {
                id: 'data-exfil',
                name: 'Potential Data Exfiltration',
                pattern: /base64[a-zA-Z0-9+/]{100,}/,
                action: 'alert',
                severity: 'high',
            },
            // WebSocket to unknown domains
            {
                id: 'suspicious-ws',
                name: 'Suspicious WebSocket',
                pattern: /^wss?:\/\/(?!localhost|127\.0\.0\.1)/,
                action: 'alert',
                severity: 'medium',
            },
            // Excessive query parameters
            {
                id: 'long-query',
                name: 'Excessive Query Parameters',
                pattern: /\?[^#]{500,}/,
                action: 'alert',
                severity: 'medium',
            },
        ];
    }

    async init(): Promise<void> {
        // Connect to sandbox
        this.api = await createSecureAPI(
            'traffic-analyzer',
            '/tmp/marshall-sandbox.sock'
        );

        // Load saved blocklist
        const saved = await this.api.storageGet('blocklist');
        if (saved) {
            this.blocklist = new Set(saved);
        }

        // Register web request interceptors
        this.setupInterceptors();

        console.log('[Traffic Analyzer] Initialized');
    }

    private setupInterceptors(): void {
        // Before request - can block
        marshall.webRequest.onBeforeRequest((details) => {
            return this.analyzeRequest(details);
        }, { urls: ['<all_urls>'] });

        // Headers received
        marshall.webRequest.onHeadersReceived((details) => {
            this.analyzeHeaders(details);
        });

        // Request completed
        marshall.webRequest.onCompleted((details) => {
            this.logCompletion(details);
        });

        // Request error
        marshall.webRequest.onErrorOccurred((details) => {
            this.logError(details);
        });
    }

    private analyzeRequest(details: any): { cancel?: boolean } {
        const url = new URL(details.url);
        const domain = url.hostname;
        const requestId = details.requestId;

        // Create log entry
        const log: RequestLog = {
            id: requestId,
            timestamp: Date.now(),
            method: details.method,
            url: details.url,
            type: details.type,
            status: 0,
            size: 0,
            duration: 0,
            initiator: details.initiator || '',
            headers: {},
            responseHeaders: {},
            blocked: false,
        };

        // Check blocklist
        if (this.blocklist.has(domain)) {
            log.blocked = true;
            log.reason = 'Domain blocklist';
            this.stats.blockedRequests++;
            this.requests.set(requestId, log);
            return { cancel: true };
        }

        // Check anomaly rules
        for (const rule of this.anomalyRules) {
            const pattern = typeof rule.pattern === 'string' 
                ? new RegExp(rule.pattern) 
                : rule.pattern;

            if (pattern.test(details.url)) {
                if (rule.action === 'block') {
                    log.blocked = true;
                    log.reason = rule.name;
                    this.stats.blockedRequests++;
                    this.requests.set(requestId, log);
                    
                    this.notifyAnomaly(rule, details);
                    return { cancel: true };
                } else if (rule.action === 'alert') {
                    this.notifyAnomaly(rule, details);
                }
            }
        }

        // Update stats
        this.stats.totalRequests++;
        this.stats.byType[details.type] = (this.stats.byType[details.type] || 0) + 1;
        this.stats.byDomain[domain] = (this.stats.byDomain[domain] || 0) + 1;
        this.stats.byMethod[details.method] = (this.stats.byMethod[details.method] || 0) + 1;

        this.requests.set(requestId, log);
        this.trimLogs();

        return {};
    }

    private analyzeHeaders(details: any): void {
        const log = this.requests.get(details.requestId);
        if (!log) return;

        // Store response headers
        if (details.responseHeaders) {
            for (const header of details.responseHeaders) {
                log.responseHeaders[header.name.toLowerCase()] = header.value;
            }
        }

        log.status = details.statusCode;
    }

    private logCompletion(details: any): void {
        const log = this.requests.get(details.requestId);
        if (!log) return;

        log.duration = Date.now() - log.timestamp;
        
        // Estimate size from content-length header
        const contentLength = log.responseHeaders['content-length'];
        if (contentLength) {
            log.size = parseInt(contentLength, 10);
            this.stats.totalBytes += log.size;
        }
    }

    private logError(details: any): void {
        const log = this.requests.get(details.requestId);
        if (!log) return;

        log.status = -1;
        log.reason = details.error;
    }

    private notifyAnomaly(rule: AnomalyRule, details: any): void {
        const severityColors = {
            low: '#3498db',
            medium: '#f39c12',
            high: '#e74c3c',
            critical: '#9b59b6',
        };

        this.api?.notify(
            `[${rule.severity.toUpperCase()}] ${rule.name}: ${new URL(details.url).hostname}`,
            rule.severity === 'critical' ? 'error' : 'warning'
        );
    }

    private trimLogs(): void {
        if (this.requests.size > this.maxLogs) {
            const sorted = Array.from(this.requests.entries())
                .sort((a, b) => a[1].timestamp - b[1].timestamp);
            
            const toRemove = sorted.slice(0, sorted.length - this.maxLogs);
            for (const [id] of toRemove) {
                this.requests.delete(id);
            }
        }
    }

    // Public API
    getStats(): TrafficStats {
        return { ...this.stats };
    }

    getLogs(filter?: Partial<RequestLog>): RequestLog[] {
        let logs = Array.from(this.requests.values());
        
        if (filter) {
            logs = logs.filter(log => {
                for (const [key, value] of Object.entries(filter)) {
                    if ((log as any)[key] !== value) return false;
                }
                return true;
            });
        }

        return logs.sort((a, b) => b.timestamp - a.timestamp);
    }

    addToBlocklist(domain: string): void {
        this.blocklist.add(domain);
        this.api?.storageSet('blocklist', Array.from(this.blocklist));
    }

    removeFromBlocklist(domain: string): void {
        this.blocklist.delete(domain);
        this.api?.storageSet('blocklist', Array.from(this.blocklist));
    }

    getBlocklist(): string[] {
        return Array.from(this.blocklist);
    }

    addRule(rule: AnomalyRule): void {
        this.anomalyRules.push(rule);
    }

    removeRule(id: string): void {
        this.anomalyRules = this.anomalyRules.filter(r => r.id !== id);
    }

    getRules(): AnomalyRule[] {
        return [...this.anomalyRules];
    }

    resetStats(): void {
        this.stats = this.initStats();
    }

    exportLogs(): string {
        return JSON.stringify({
            stats: this.stats,
            logs: this.getLogs(),
            exported: new Date().toISOString(),
        }, null, 2);
    }

    showDashboard(): void {
        const html = this.generateDashboardHTML();
        this.api?.showPanel(html, {
            title: 'Traffic Analyzer',
            width: 800,
            height: 600,
        });
    }

    private generateDashboardHTML(): string {
        const topDomains = Object.entries(this.stats.byDomain)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10);

        return `
            <div class="traffic-dashboard">
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Requests</h3>
                        <span class="stat-value">${this.stats.totalRequests.toLocaleString()}</span>
                    </div>
                    <div class="stat-card blocked">
                        <h3>Blocked</h3>
                        <span class="stat-value">${this.stats.blockedRequests.toLocaleString()}</span>
                    </div>
                    <div class="stat-card">
                        <h3>Data Transfer</h3>
                        <span class="stat-value">${this.formatBytes(this.stats.totalBytes)}</span>
                    </div>
                </div>

                <div class="section">
                    <h3>Top Domains</h3>
                    <table>
                        <thead>
                            <tr><th>Domain</th><th>Requests</th><th>Actions</th></tr>
                        </thead>
                        <tbody>
                            ${topDomains.map(([domain, count]) => `
                                <tr>
                                    <td>${domain}</td>
                                    <td>${count}</td>
                                    <td>
                                        <button onclick="trafficAnalyzer.addToBlocklist('${domain}')">
                                            Block
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>

                <div class="section">
                    <h3>Recent Blocked Requests</h3>
                    <ul class="blocked-list">
                        ${this.getLogs({ blocked: true }).slice(0, 10).map(log => `
                            <li>
                                <span class="url">${log.url.substring(0, 60)}...</span>
                                <span class="reason">${log.reason}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>

                <div class="actions">
                    <button onclick="trafficAnalyzer.exportLogs()">Export Logs</button>
                    <button onclick="trafficAnalyzer.resetStats()">Reset Stats</button>
                </div>
            </div>
        `;
    }

    private formatBytes(bytes: number): string {
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) {
            bytes /= 1024;
            i++;
        }
        return `${bytes.toFixed(1)} ${units[i]}`;
    }
}

// Extension entry point
const trafficAnalyzer = new TrafficAnalyzer();

marshall.extension.onActivate(async () => {
    await trafficAnalyzer.init();
    
    // Register toolbar button
    marshall.toolbar.register({
        id: 'traffic-analyzer',
        icon: '📊',
        title: 'Traffic Analyzer',
        onclick: () => trafficAnalyzer.showDashboard(),
    });
});

marshall.extension.onDeactivate(() => {
    console.log('[Traffic Analyzer] Deactivated');
});

// Export API
marshall.extension.export('getStats', () => trafficAnalyzer.getStats());
marshall.extension.export('getLogs', (f: any) => trafficAnalyzer.getLogs(f));
marshall.extension.export('block', (d: string) => trafficAnalyzer.addToBlocklist(d));
