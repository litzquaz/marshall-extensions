//! Secure Communication Channel
//! 
//! Encrypted IPC channel between sandbox and Marshall browser

use std::sync::mpsc::{channel, Sender, Receiver};
use std::collections::VecDeque;

/// Message types for sandbox <-> Marshall communication
#[derive(Debug, Clone)]
pub enum Message {
    // Extension -> Marshall
    ApiRequest {
        request_id: u64,
        api: String,
        payload: Vec<u8>,
    },
    ThreatAlert {
        threat_type: String,
        severity: u8,
        details: String,
    },
    StatusReport {
        memory_used: usize,
        api_calls: u64,
        uptime_secs: u64,
    },
    
    // Marshall -> Extension
    ApiResponse {
        request_id: u64,
        success: bool,
        payload: Vec<u8>,
    },
    PermissionGrant {
        permission: String,
        granted: bool,
    },
    Terminate {
        reason: String,
    },
}

/// Encrypted channel for secure communication
pub struct SecureChannel {
    // In production, this would use Unix domain sockets or shared memory
    // with encryption (e.g., Noise Protocol)
    outbound: VecDeque<Message>,
    session_key: [u8; 32],
    request_counter: u64,
}

impl SecureChannel {
    pub fn new() -> Self {
        // Generate ephemeral session key
        let mut session_key = [0u8; 32];
        // In production: use ring::rand::SystemRandom
        for (i, byte) in session_key.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(42);
        }
        
        Self {
            outbound: VecDeque::new(),
            session_key,
            request_counter: 0,
        }
    }
    
    /// Establish encrypted channel with Marshall
    pub fn handshake(&mut self) -> Result<(), ChannelError> {
        // Perform key exchange (simplified)
        // In production: X25519 key exchange + ChaCha20-Poly1305
        Ok(())
    }
    
    /// Send API request to Marshall
    pub fn send_api_request(&mut self, api: &str, payload: &[u8]) -> u64 {
        self.request_counter += 1;
        let request_id = self.request_counter;
        
        let msg = Message::ApiRequest {
            request_id,
            api: api.to_string(),
            payload: payload.to_vec(),
        };
        
        self.outbound.push_back(msg);
        request_id
    }
    
    /// Send threat alert to Marshall
    pub fn send_threat_alert(&mut self, threat_type: &super::ThreatType, severity: u8) {
        let msg = Message::ThreatAlert {
            threat_type: format!("{:?}", threat_type),
            severity,
            details: String::new(),
        };
        
        self.outbound.push_back(msg);
    }
    
    /// Encrypt a message
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        // Simplified XOR encryption for demo
        // In production: ChaCha20-Poly1305 or AES-GCM
        plaintext.iter()
            .enumerate()
            .map(|(i, b)| b ^ self.session_key[i % 32])
            .collect()
    }
    
    /// Decrypt a message  
    fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        // XOR is symmetric
        self.encrypt(ciphertext)
    }
}

#[derive(Debug)]
pub struct ChannelError {
    pub message: String,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Channel error: {}", self.message)
    }
}

impl std::error::Error for ChannelError {}
