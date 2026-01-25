//! Marshall Extension Sandbox - Secure Runtime Container
//! 
//! A firewalled sandbox environment for running Marshall browser extensions
//! with isolation, verification, and honeypot integration.
//!
//! Part of the NullSec Security Suite

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

mod isolation;
mod verification;
mod channel;

/// Sandbox security level
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SecurityLevel {
    /// Minimal restrictions - trusted extensions
    Trusted,
    /// Standard sandboxing - verified extensions  
    Standard,
    /// Maximum isolation - untested/suspicious extensions
    Paranoid,
}

/// Extension permission flags
#[derive(Debug, Clone)]
pub struct Permissions {
    pub network_access: bool,
    pub file_read: bool,
    pub file_write: bool,
    pub dom_access: bool,
    pub storage_access: bool,
    pub clipboard_access: bool,
    pub context_menu: bool,
    pub background_scripts: bool,
    pub cross_origin: bool,
    pub native_messaging: bool,
}

impl Default for Permissions {
    fn default() -> Self {
        Self {
            network_access: false,
            file_read: false,
            file_write: false,
            dom_access: true,
            storage_access: true,
            clipboard_access: false,
            context_menu: true,
            background_scripts: false,
            cross_origin: false,
            native_messaging: false,
        }
    }
}

/// Suspicious activity indicators
#[derive(Debug, Clone)]
pub struct ThreatIndicator {
    pub timestamp: Instant,
    pub indicator_type: ThreatType,
    pub source: String,
    pub details: String,
    pub severity: u8, // 1-10
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreatType {
    UnauthorizedNetworkAccess,
    SandboxEscapeAttempt,
    MemoryCorruption,
    CodeInjection,
    PrivilegeEscalation,
    DataExfiltration,
    AnomalousPattern,
    ResourceAbuse,
    CryptoMining,
    Fingerprinting,
}

/// Sandbox container for a single extension
pub struct ExtensionSandbox {
    pub id: String,
    pub name: String,
    pub version: String,
    pub security_level: SecurityLevel,
    pub permissions: Permissions,
    pub verified: bool,
    pub signature: Option<String>,
    
    // Runtime state
    memory_limit: usize,
    cpu_quota: f64,
    network_quota: usize,
    
    // Monitoring
    threat_indicators: Vec<ThreatIndicator>,
    api_calls: Vec<ApiCall>,
    start_time: Instant,
    
    // Communication channel to Marshall
    channel: channel::SecureChannel,
}

#[derive(Debug, Clone)]
pub struct ApiCall {
    pub timestamp: Instant,
    pub api: String,
    pub args_hash: String,
    pub allowed: bool,
    pub duration_us: u64,
}

impl ExtensionSandbox {
    pub fn new(id: &str, name: &str, version: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            security_level: SecurityLevel::Standard,
            permissions: Permissions::default(),
            verified: false,
            signature: None,
            memory_limit: 50 * 1024 * 1024, // 50MB
            cpu_quota: 0.25, // 25% of one core
            network_quota: 10 * 1024 * 1024, // 10MB
            threat_indicators: Vec::new(),
            api_calls: Vec::new(),
            start_time: Instant::now(),
            channel: channel::SecureChannel::new(),
        }
    }
    
    /// Verify extension signature and integrity
    pub fn verify(&mut self, public_key: &[u8]) -> Result<bool, SandboxError> {
        let signature = self.signature.as_ref()
            .ok_or(SandboxError::NoSignature)?;
        
        // Verify cryptographic signature
        let valid = verification::verify_signature(
            &self.id,
            signature,
            public_key
        )?;
        
        self.verified = valid;
        
        if valid {
            // Upgrade to trusted if verified
            self.security_level = SecurityLevel::Trusted;
        }
        
        Ok(valid)
    }
    
    /// Check if an API call is permitted
    pub fn check_permission(&self, api: &str) -> bool {
        match api {
            "network.fetch" | "network.websocket" => self.permissions.network_access,
            "fs.read" | "storage.get" => self.permissions.file_read || self.permissions.storage_access,
            "fs.write" | "storage.set" => self.permissions.file_write || self.permissions.storage_access,
            "dom.query" | "dom.modify" => self.permissions.dom_access,
            "clipboard.read" | "clipboard.write" => self.permissions.clipboard_access,
            "contextMenu.register" => self.permissions.context_menu,
            _ => false,
        }
    }
    
    /// Record an API call for monitoring
    pub fn record_api_call(&mut self, api: &str, args_hash: &str, allowed: bool, duration_us: u64) {
        self.api_calls.push(ApiCall {
            timestamp: Instant::now(),
            api: api.to_string(),
            args_hash: args_hash.to_string(),
            allowed,
            duration_us,
        });
        
        // Detect anomalous patterns
        self.analyze_behavior();
    }
    
    /// Analyze extension behavior for threats
    fn analyze_behavior(&mut self) {
        let recent_calls: Vec<_> = self.api_calls.iter()
            .filter(|c| c.timestamp.elapsed() < Duration::from_secs(60))
            .collect();
        
        // Check for rapid API calls (potential abuse)
        if recent_calls.len() > 1000 {
            self.flag_threat(ThreatType::ResourceAbuse, 
                "extension", 
                "Excessive API calls detected",
                5);
        }
        
        // Check for denied calls (potential probing)
        let denied_count = recent_calls.iter().filter(|c| !c.allowed).count();
        if denied_count > 50 {
            self.flag_threat(ThreatType::SandboxEscapeAttempt,
                "extension",
                "Multiple permission violations",
                7);
        }
        
        // Check for network + storage combo (data exfil pattern)
        let has_network = recent_calls.iter().any(|c| c.api.starts_with("network.") && c.allowed);
        let has_storage = recent_calls.iter().any(|c| c.api.starts_with("storage.") && c.allowed);
        if has_network && has_storage && recent_calls.len() > 100 {
            self.flag_threat(ThreatType::DataExfiltration,
                "extension",
                "Suspicious network+storage access pattern",
                6);
        }
    }
    
    /// Flag a potential threat
    pub fn flag_threat(&mut self, threat_type: ThreatType, source: &str, details: &str, severity: u8) {
        let indicator = ThreatIndicator {
            timestamp: Instant::now(),
            indicator_type: threat_type.clone(),
            source: source.to_string(),
            details: details.to_string(),
            severity,
        };
        
        self.threat_indicators.push(indicator);
        
        // Escalate security level based on severity
        if severity >= 7 {
            self.security_level = SecurityLevel::Paranoid;
            // Notify honeypot system
            self.channel.send_threat_alert(&threat_type, severity);
        }
    }
    
    /// Get threat score (0-100)
    pub fn threat_score(&self) -> u32 {
        let recent: Vec<_> = self.threat_indicators.iter()
            .filter(|t| t.timestamp.elapsed() < Duration::from_secs(300))
            .collect();
        
        let score: u32 = recent.iter()
            .map(|t| t.severity as u32 * 10)
            .sum();
        
        score.min(100)
    }
}

/// Global sandbox manager
pub struct SandboxManager {
    sandboxes: Arc<RwLock<HashMap<String, ExtensionSandbox>>>,
    honeypot_enabled: bool,
    threat_threshold: u32,
}

impl SandboxManager {
    pub fn new() -> Self {
        Self {
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
            honeypot_enabled: true,
            threat_threshold: 50,
        }
    }
    
    /// Create and register a new sandbox
    pub fn create_sandbox(&self, id: &str, name: &str, version: &str) -> Result<(), SandboxError> {
        let sandbox = ExtensionSandbox::new(id, name, version);
        
        let mut sandboxes = self.sandboxes.write()
            .map_err(|_| SandboxError::LockError)?;
        
        sandboxes.insert(id.to_string(), sandbox);
        Ok(())
    }
    
    /// Execute an API call within sandbox
    pub fn execute_api(&self, sandbox_id: &str, api: &str, args: &[u8]) -> Result<Vec<u8>, SandboxError> {
        let mut sandboxes = self.sandboxes.write()
            .map_err(|_| SandboxError::LockError)?;
        
        let sandbox = sandboxes.get_mut(sandbox_id)
            .ok_or(SandboxError::NotFound)?;
        
        // Check threat level
        if sandbox.threat_score() >= self.threat_threshold {
            if self.honeypot_enabled {
                // Redirect to honeypot
                return self.redirect_to_honeypot(sandbox_id, api, args);
            } else {
                return Err(SandboxError::Quarantined);
            }
        }
        
        // Check permission
        let start = Instant::now();
        let allowed = sandbox.check_permission(api);
        
        let result = if allowed {
            // Execute in isolation
            isolation::execute_isolated(api, args)
        } else {
            Err(SandboxError::PermissionDenied(api.to_string()))
        };
        
        let duration = start.elapsed().as_micros() as u64;
        let args_hash = format!("{:x}", md5::compute(args));
        
        sandbox.record_api_call(api, &args_hash, allowed, duration);
        
        result
    }
    
    /// Redirect suspicious extension to honeypot
    fn redirect_to_honeypot(&self, sandbox_id: &str, api: &str, args: &[u8]) -> Result<Vec<u8>, SandboxError> {
        // Send to honeypot service via channel
        // Returns fake but believable data
        println!("[SANDBOX] Redirecting {} to honeypot for API: {}", sandbox_id, api);
        
        // Generate honeypot response based on API
        let fake_response = match api {
            "network.fetch" => b"{ \"status\": \"ok\", \"data\": [] }".to_vec(),
            "storage.get" => b"null".to_vec(),
            "dom.query" => b"[]".to_vec(),
            _ => b"{}".to_vec(),
        };
        
        Ok(fake_response)
    }
    
    /// Get all active threats
    pub fn get_threats(&self) -> Vec<(String, Vec<ThreatIndicator>)> {
        let sandboxes = self.sandboxes.read().unwrap();
        
        sandboxes.iter()
            .filter(|(_, s)| !s.threat_indicators.is_empty())
            .map(|(id, s)| (id.clone(), s.threat_indicators.clone()))
            .collect()
    }
}

#[derive(Debug)]
pub enum SandboxError {
    NotFound,
    PermissionDenied(String),
    Quarantined,
    NoSignature,
    InvalidSignature,
    LockError,
    IsolationError(String),
    ChannelError(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Sandbox not found"),
            Self::PermissionDenied(api) => write!(f, "Permission denied for API: {}", api),
            Self::Quarantined => write!(f, "Extension quarantined due to threats"),
            Self::NoSignature => write!(f, "Extension has no signature"),
            Self::InvalidSignature => write!(f, "Invalid extension signature"),
            Self::LockError => write!(f, "Failed to acquire lock"),
            Self::IsolationError(e) => write!(f, "Isolation error: {}", e),
            Self::ChannelError(e) => write!(f, "Channel error: {}", e),
        }
    }
}

impl std::error::Error for SandboxError {}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sandbox_creation() {
        let sandbox = ExtensionSandbox::new("test-ext", "Test Extension", "1.0.0");
        assert_eq!(sandbox.security_level, SecurityLevel::Standard);
        assert!(!sandbox.verified);
    }
    
    #[test]
    fn test_permission_check() {
        let mut sandbox = ExtensionSandbox::new("test", "Test", "1.0.0");
        
        // Default permissions
        assert!(sandbox.check_permission("dom.query"));
        assert!(!sandbox.check_permission("network.fetch"));
        
        // Grant network permission
        sandbox.permissions.network_access = true;
        assert!(sandbox.check_permission("network.fetch"));
    }
    
    #[test]
    fn test_threat_detection() {
        let mut sandbox = ExtensionSandbox::new("test", "Test", "1.0.0");
        
        sandbox.flag_threat(ThreatType::SandboxEscapeAttempt, "test", "Test threat", 8);
        
        assert!(sandbox.threat_score() > 0);
        assert_eq!(sandbox.security_level, SecurityLevel::Paranoid);
    }
}
