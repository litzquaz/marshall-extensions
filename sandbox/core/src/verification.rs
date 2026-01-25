//! Extension Verification Module
//!
//! Cryptographic verification of extension signatures and integrity

use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use ring::digest::{Context, SHA256};

/// Verify extension signature
pub fn verify_signature(
    extension_id: &str,
    signature: &str,
    public_key: &[u8],
) -> Result<bool, super::SandboxError> {
    let sig_bytes = hex::decode(signature)
        .map_err(|_| super::SandboxError::InvalidSignature)?;
    
    let public_key = UnparsedPublicKey::new(&ED25519, public_key);
    
    let message = extension_id.as_bytes();
    
    match public_key.verify(message, &sig_bytes) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Calculate SHA-256 hash of extension content
pub fn hash_extension(content: &[u8]) -> String {
    let mut context = Context::new(&SHA256);
    context.update(content);
    let digest = context.finish();
    
    hex::encode(digest.as_ref())
}

/// Verify extension manifest integrity
pub fn verify_manifest(manifest: &str, expected_hash: &str) -> bool {
    let actual_hash = hash_extension(manifest.as_bytes());
    actual_hash == expected_hash
}

/// Extension verification result
#[derive(Debug)]
pub struct VerificationResult {
    pub valid_signature: bool,
    pub valid_hash: bool,
    pub trusted_source: bool,
    pub known_malware: bool,
    pub risk_score: u8, // 0-100
}

impl VerificationResult {
    pub fn is_safe(&self) -> bool {
        self.valid_signature && self.valid_hash && !self.known_malware && self.risk_score < 50
    }
}

/// Check extension against malware database
pub fn check_malware_db(hash: &str) -> bool {
    // In production, check against known malicious extension hashes
    // This would query a local or remote database
    
    const KNOWN_MALICIOUS: &[&str] = &[
        "badextension123...",
        "malware456...",
    ];
    
    KNOWN_MALICIOUS.contains(&hash)
}

// Dependency for hex encoding
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
    
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
