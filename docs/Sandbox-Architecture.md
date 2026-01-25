# 🔒 Sandbox Architecture

The Marshall Extensions sandbox provides a secure, isolated environment for running untrusted extension code.

---

## Overview

```mermaid
flowchart TB
    subgraph Browser["🌐 Marshall Browser"]
        subgraph CommLayer["📡 Secure Communication Layer<br/><i>TypeScript • AES-256-GCM</i>"]
            ECDH["🔑 ECDH<br/>Key Exchange"]
            Sign["✍️ Message<br/>Signing"]
            Replay["🛡️ Replay<br/>Protection"]
        end
        
        subgraph SandboxCore["🦀 Sandbox Core Runtime<br/><i>Rust • libseccomp</i>"]
            Isolation["🔒 Isolation<br/>Engine"]
            Verify["✅ Verification<br/>Ed25519"]
            Threat["⚠️ Threat<br/>Detection"]
        end
        
        subgraph Honeypot["🍯 Honeypot System<br/><i>Go • Deception Services</i>"]
            NetHP["🌐 Network"]
            ApiHP["🔌 API"]
            FileHP["📁 File"]
            DataHP["🔑 Data"]
        end
    end
    
    Ext["🧩 Extension"] ==> CommLayer
    CommLayer ==> SandboxCore
    SandboxCore ==> Honeypot
    Threat -.->|"Threat Score > 50"| Honeypot
    
    style Browser fill:#0d1117,stroke:#30363d,stroke-width:3px,color:#c9d1d9
    style CommLayer fill:#161b22,stroke:#6e40c9,stroke-width:2px,color:#c9d1d9
    style SandboxCore fill:#161b22,stroke:#da3633,stroke-width:2px,color:#c9d1d9
    style Honeypot fill:#161b22,stroke:#238636,stroke-width:2px,color:#c9d1d9
    style Ext fill:#21262d,stroke:#58a6ff,stroke-width:2px,color:#c9d1d9
```

### Architecture Layers

| Layer | Language | Key Features |
|-------|----------|--------------|
| **🔐 Communication** | TypeScript | AES-256-GCM encryption, ECDH key exchange, replay protection |
| **🦀 Sandbox Core** | Rust | seccomp syscall filtering, namespace isolation, threat scoring |
| **🍯 Honeypot** | Go | Fake services, credential honeytokens, intrusion detection |

---

## Components

### 1. Secure Communication Layer (TypeScript)

**Location:** `sandbox/comm/`

The communication layer provides encrypted IPC between extensions and the browser.

#### Features
- **AES-256-GCM encryption** for all messages
- **ECDH key exchange** for session keys
- **Message signing** for integrity
- **Replay protection** with nonces

#### API

```typescript
import { SecureChannel, SandboxedAPI } from './channel';

// Create secure channel
const channel = new SecureChannel(extensionId);

// Perform handshake
await channel.performHandshake();

// Send encrypted message
const response = await channel.send({
  type: 'api_call',
  method: 'network.fetch',
  args: ['https://example.com']
});
```

---

### 2. Sandbox Core Runtime (Rust)

**Location:** `sandbox/core/`

The Rust sandbox provides process-level isolation and threat detection.

#### Security Levels

```rust
pub enum SecurityLevel {
    Minimal,    // Basic isolation
    Standard,   // Default - seccomp + limited syscalls
    Strict,     // Maximum isolation
    Paranoid,   // All protections + honeypot enabled
}
```

#### Permission System

```rust
pub struct Permissions {
    pub network: bool,       // HTTP requests
    pub filesystem: bool,    // File access
    pub process: bool,       // Process spawning
    pub clipboard: bool,     // Clipboard access
    pub notifications: bool, // System notifications
    pub dom_access: bool,    // Page DOM access
    pub storage: bool,       // Persistent storage
}
```

#### Threat Detection

The sandbox monitors for suspicious behavior:

| Indicator | Description | Score |
|-----------|-------------|-------|
| `SuspiciousApiCall` | Blocked API call | +10 |
| `ExcessiveNetworkRequests` | Too many requests | +5 |
| `UnauthorizedFileAccess` | File system access | +15 |
| `CredentialAccess` | Credential harvesting | +25 |
| `MemoryScanning` | Process memory access | +20 |
| `AnomalousBehavior` | Pattern mismatch | +8 |

**Threshold**: Score > 50 triggers honeypot redirection

#### Isolation Features

- **seccomp-bpf** - System call filtering
- **Namespace isolation** - PID, network, mount, user namespaces
- **Resource limits** - CPU, memory, file descriptors
- **Capability dropping** - Minimal privileges

---

### 3. Honeypot System (Go)

**Location:** `sandbox/honeypot/`

The honeypot provides deception services to detect and analyze malicious extensions.

#### Honeypot Types

##### Network Honeypot
Fake network services that log connection attempts:

```go
type NetworkHoneypot struct {
    listener net.Listener
    ports    []int  // Fake open ports
}
```

##### API Honeypot
Fake API endpoints that return convincing but fake data:

```go
type APIHoneypot struct {
    endpoints map[string]FakeEndpoint
}

// Fake endpoints:
// /api/v1/credentials - Returns fake credentials
// /api/v1/keys - Returns fake API keys
// /api/v1/users - Returns fake user data
```

##### File Honeypot
Honeytoken files that trigger alerts when accessed:

```go
type FileHoneypot struct {
    files []string
}

// Fake files:
// ~/.ssh/id_rsa (fake SSH key)
// ~/.aws/credentials (fake AWS creds)
// ~/.config/secrets.json (fake secrets)
```

##### Data Honeypot
Fake sensitive data injected into extension context:

```go
type DataHoneypot struct {
    fakeCredentials map[string]string
}

// Example fake data:
// AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE
// DB_PASSWORD = fake_password_honeypot
```

#### Event Logging

All honeypot interactions are logged:

```go
type ThreatEvent struct {
    Timestamp    time.Time
    ExtensionID  string
    EventType    string      // "network", "api", "file", "data"
    Details      string
    SourceIP     string
    UserAgent    string
    Severity     int         // 1-10
}
```

---

## Extension Lifecycle

### 1. Loading

```mermaid
flowchart LR
    A["📦 Extension<br/>Package"] --> B["🔐 Verification<br/>Ed25519"]
    B -->|Valid| C["📋 Permission<br/>Parsing"]
    C --> D["📦 Sandbox<br/>Creation"]
    D --> E["🔑 Key<br/>Exchange"]
    E --> F["✅ Running"]
    
    B -->|Invalid| X["❌ Rejected"]
    
    style A fill:#21262d,stroke:#58a6ff
    style F fill:#238636,stroke:#3fb950
    style X fill:#da3633,stroke:#f85149
```

### 2. API Calls

```mermaid
sequenceDiagram
    participant E as 🧩 Extension
    participant S as 🦀 Sandbox
    participant B as 🌐 Browser
    
    E->>S: API Request
    S->>S: Permission Check
    S->>S: Threat Scoring
    S->>B: Encrypted Request
    B->>S: Encrypted Response
    S->>E: API Response
```

### 3. Threat Response

```mermaid
flowchart LR
    A["⚠️ High Threat<br/>Score"] --> B["📝 Log<br/>Incident"]
    B --> C["🍯 Redirect to<br/>Honeypot"]
    C --> D["👁️ Continue<br/>Monitoring"]
    D --> E["📊 Generate<br/>Report"]
    
    style A fill:#da3633,stroke:#f85149
    style C fill:#238636,stroke:#3fb950
```

---

## Configuration

### Sandbox Config

```toml
# sandbox.toml

[security]
level = "standard"  # minimal, standard, strict, paranoid
threat_threshold = 50

[isolation]
enable_seccomp = true
enable_namespaces = true
max_memory_mb = 256
max_cpu_percent = 25

[honeypot]
enabled = true
network_ports = [22, 23, 3389, 5900]
fake_credentials = true
file_honeytokens = true

[logging]
level = "info"
threat_events = true
api_calls = false
```

### Per-Extension Config

```json
{
  "extension_id": "shodan-lookup",
  "security_level": "standard",
  "permissions": {
    "network": true,
    "storage": true
  },
  "rate_limits": {
    "requests_per_minute": 60
  }
}
```

---

## Development

### Building the Sandbox

```bash
# Build Rust core
cd sandbox/core
cargo build --release

# Build Go honeypot
cd sandbox/honeypot
go build -o honeypot

# Build TypeScript channel
cd sandbox/comm
npm install
npm run build
```

### Testing

```bash
# Run Rust tests
cd sandbox/core
cargo test

# Run Go tests
cd sandbox/honeypot
go test ./...

# Run TypeScript tests
cd sandbox/comm
npm test
```

---

## Security Considerations

### What the Sandbox Protects Against

- ✅ Malicious extensions stealing data
- ✅ Extensions escaping to host system
- ✅ Network-based attacks
- ✅ File system access
- ✅ Credential theft
- ✅ Memory scanning

### Limitations

- ⚠️ Cannot prevent all side-channel attacks
- ⚠️ Determined attackers may find bypasses
- ⚠️ Performance overhead (~5-10%)
- ⚠️ Some legitimate extensions may be flagged

### Reporting Vulnerabilities

Found a security issue? Please report responsibly:
1. Do NOT open a public issue
2. Email security@nullsec.local
3. Include reproduction steps
4. Allow 90 days for fix before disclosure
