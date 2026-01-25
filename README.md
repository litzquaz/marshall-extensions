# 🔌 Marshall Extensions

**OSINT & Security Extensions for Marshall Browser**

A collection of installable plugins and extensions that enhance Marshall Browser with additional security testing and reconnaissance capabilities. All extensions run through a **secure sandboxed container** with honeypot detection.

## 🔒 Secure Sandbox Architecture

All extensions are executed within a multi-layered security sandbox:

```
┌────────────────────────────────────────────────────────────────┐
│                    Marshall Browser                             │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Secure Communication Layer                   │  │
│  │         (TypeScript - AES-256-GCM Encrypted)             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Sandbox Core Runtime                         │  │
│  │            (Rust - seccomp/namespace)                     │  │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │  │
│  │  │ Isolation   │ │ Verification│ │ Threat Detection    │ │  │
│  │  │ Engine      │ │ (Ed25519)   │ │ (Score-based)       │ │  │
│  │  └─────────────┘ └─────────────┘ └─────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Honeypot System                              │  │
│  │            (Go - Adaptive Deception)                      │  │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────────────┐ │  │
│  │  │Network │ │ API    │ │ File   │ │ Data Honeytokens   │ │  │
│  │  │Honeypot│ │Honeypot│ │Honeypot│ │ (Fake Credentials) │ │  │
│  │  └────────┘ └────────┘ └────────┘ └────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### Sandbox Components

| Component | Language | Purpose |
|-----------|----------|---------|
| `sandbox/core/` | Rust | Process isolation, threat scoring, permission enforcement |
| `sandbox/honeypot/` | Go | Deception system, fake services, intrusion detection |
| `sandbox/comm/` | TypeScript | Encrypted IPC, key exchange, message signing |

## 📦 Available Extensions

### Recon Extensions
- **🔍 Shodan Lookup** - Query Shodan.io for IP/domain intelligence
- **📋 WHOIS Inspector** - Detailed domain registration info
- **⚡ XSS Scanner** - Detect Cross-Site Scripting vulnerabilities
- **📝 Header Analyzer** - Security header analysis and recommendations
- **🔐 Cert Inspector** *(Ruby)* - SSL/TLS certificate analysis with grading

### Forensics Extensions
- **🧠 Memory Forensics** *(C)* - Memory artifact detection, shellcode patterns

### Network Extensions  
- **📡 Traffic Analyzer** *(TypeScript)* - Network monitoring, anomaly detection

### Utility Extensions
- **🔧 Request Tamper** *(Lua)* - HTTP interception, modification, replay
- **📊 Request Logger** - Log and export all HTTP requests
- **🎨 Response Beautifier** - Format JSON, XML, HTML responses
- **⏱️ Performance Analyzer** - Page load timing and metrics
- **📸 Screenshot Tool** - Full page and element screenshots

### Multi-Language Stack
Extensions are written in various languages for versatility:
- **Rust** - Core sandbox runtime
- **Go** - Honeypot system  
- **TypeScript** - Communication layer, network extensions
- **C** - Low-level forensics
- **Ruby** - Certificate analysis
- **Lua** - Scripting/request manipulation
- **JavaScript** - UI extensions

## 🚀 Installation

### Method 1: Marshall Extension Manager
1. Open Marshall Browser
2. Go to `Settings > Extensions`
3. Click "Install from Repository"
4. Select extensions to install

### Method 2: Manual Installation
1. Clone this repository
2. Copy desired extension folder to `~/.marshall/extensions/`
3. Restart Marshall Browser
4. Enable extension in Settings

```bash
git clone https://github.com/bad-antics/marshall-extensions.git
cp -r marshall-extensions/osint/shodan-lookup ~/.marshall/extensions/
```

## 📁 Project Structure

```
marshall-extensions/
├── sandbox/                    # Secure container system
│   ├── core/                   # Rust sandbox runtime
│   │   ├── src/
│   │   │   ├── lib.rs          # Main sandbox logic
│   │   │   ├── isolation.rs    # Process isolation
│   │   │   ├── verification.rs # Signature verification
│   │   │   └── channel.rs      # IPC messaging
│   │   └── Cargo.toml
│   ├── honeypot/               # Go honeypot system
│   │   ├── main.go             # Deception services
│   │   └── go.mod
│   └── comm/                   # TypeScript secure channel
│       ├── channel.ts          # Encrypted communication
│       ├── package.json
│       └── tsconfig.json
├── extensions/
│   ├── recon/                  # Reconnaissance tools
│   │   ├── shodan-lookup/
│   │   ├── whois-inspector/
│   │   ├── xss-scanner/
│   │   ├── header-analyzer/
│   │   └── cert-inspector/     # Ruby
│   ├── forensics/              # Digital forensics
│   │   └── memory-forensics/   # C
│   ├── network/                # Network analysis
│   │   └── traffic-analyzer/   # TypeScript
│   └── utility/                # Utility tools
│       └── request-tamper/     # Lua
└── lib/
    ├── marshall-api.js
    └── common-utils.js
```

## 🛠️ Extension Development

### Creating a New Extension

Each extension requires:
- `manifest.json` - Extension metadata
- `main.js` - Main extension code
- `icon.png` - Extension icon (128x128)
- `README.md` - Documentation

### Manifest Example

```json
{
  "name": "My Extension",
  "version": "1.0.0",
  "description": "Description here",
  "author": "bad-antics",
  "permissions": ["activeTab", "storage", "network"],
  "main": "main.js",
  "icon": "icon.png",
  "category": "osint"
}
```

### Marshall Extension API

```javascript
// Access current tab
marshall.tabs.getCurrent().then(tab => {
  console.log(tab.url);
});

// Make requests
marshall.network.fetch(url, options).then(response => {
  // Handle response
});

// Store data
marshall.storage.set('key', value);
marshall.storage.get('key').then(value => {});

// UI interactions
marshall.ui.showPanel(html);
marshall.ui.notify('Message', 'success');
```

## 📖 Documentation

See the [Wiki](https://github.com/bad-antics/marshall-extensions/wiki) for detailed documentation on:
- Extension development guide
- API reference
- Best practices
- Contributing guidelines

## ⚠️ Disclaimer

These extensions are provided for **educational and authorized security testing purposes only**. Always obtain proper authorization before testing systems you don't own.

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

## 🔗 Related Projects

- [Marshall Browser](https://github.com/bad-antics/marshall) - The OSINT-focused browser
- [NullSec Tools](https://github.com/bad-antics/nullsec-tools) - Security toolkit collection
- [NullSec Linux](https://github.com/bad-antics/nullsec-linux) - Security-focused Linux distro

---

<p align="center">
  <b>Part of the NullSec Security Suite</b><br>
  <a href="https://github.com/bad-antics">@bad-antics</a>
</p>
