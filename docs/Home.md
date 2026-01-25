# 🔌 Marshall Extensions Documentation

Welcome to the Marshall Extensions documentation! A collection of OSINT and security testing extensions for the Marshall Browser.

---

## 📖 Documentation Index

| Section | Description |
|---------|-------------|
| [Getting Started](Getting-Started.md) | Quick start guide |
| [Extension Development](Extension-Development.md) | Build your own extensions |
| [Sandbox Architecture](Sandbox-Architecture.md) | Security sandbox details |
| [API Reference](API-Reference.md) | Marshall API documentation |
| [Extensions Catalog](Extensions-Catalog.md) | Available extensions |
| [Contributing](Contributing.md) | How to contribute |

---

## 🚀 Quick Start

### Installing Extensions

```bash
# Clone the repository
git clone https://github.com/bad-antics/marshall-extensions.git

# Install extension in Marshall
marshall --install-extension extensions/recon/shodan-lookup
```

### From Marshall Browser

1. Open Marshall Browser
2. Navigate to `marshall://extensions`
3. Browse or search for extensions
4. Click "Install"

---

## 🔒 Secure Sandbox Architecture

All extensions run inside a secure sandbox with:

- **Rust Sandbox Core** - Process isolation with seccomp/namespaces
- **Go Honeypot System** - Deception and intrusion detection
- **TypeScript Secure Channel** - Encrypted communication

```
┌────────────────────────────────────────┐
│           Marshall Browser              │
├────────────────────────────────────────┤
│       Secure Communication Layer        │
│      (AES-256-GCM Encrypted)           │
├────────────────────────────────────────┤
│         Sandbox Core Runtime            │
│   (Rust - seccomp/namespace isolation)  │
├────────────────────────────────────────┤
│          Honeypot System                │
│     (Go - Threat Detection)            │
└────────────────────────────────────────┘
```

---

## 📦 Available Extensions

### Recon
| Extension | Language | Description |
|-----------|----------|-------------|
| **shodan-lookup** | JavaScript | Shodan.io queries |
| **whois-inspector** | JavaScript | WHOIS lookups |
| **xss-scanner** | JavaScript | XSS vulnerability detection |
| **header-analyzer** | JavaScript | Security header analysis |
| **cert-inspector** | Ruby | SSL/TLS certificate grading |

### Forensics
| Extension | Language | Description |
|-----------|----------|-------------|
| **memory-forensics** | C | Memory artifact detection |

### Network
| Extension | Language | Description |
|-----------|----------|-------------|
| **traffic-analyzer** | TypeScript | Network traffic monitoring |

### Utility
| Extension | Language | Description |
|-----------|----------|-------------|
| **request-tamper** | Lua | HTTP request interception |

---

## 🛠️ Multi-Language Stack

Extensions can be written in multiple languages:

| Language | Use Case | Example |
|----------|----------|---------|
| JavaScript | UI extensions, web tools | shodan-lookup |
| TypeScript | Complex tools, APIs | traffic-analyzer |
| Ruby | Scripting, analysis | cert-inspector |
| Lua | Request manipulation | request-tamper |
| C | Performance-critical | memory-forensics |
| Rust | Sandbox integration | Custom extensions |

---

## 🔧 Extension Structure

```
my-extension/
├── manifest.json      # Extension metadata
├── main.js           # Entry point
├── lib/              # Libraries
├── assets/           # Icons, images
└── README.md         # Documentation
```

### Manifest Example

```json
{
  "name": "my-extension",
  "version": "1.0.0",
  "description": "My awesome extension",
  "main": "main.js",
  "author": "Your Name",
  "permissions": ["network", "tabs", "storage"],
  "category": "recon",
  "icon": "assets/icon.png"
}
```

---

## 🔐 Security Model

### Permissions
Extensions must declare required permissions:

| Permission | Access |
|------------|--------|
| `network` | Make HTTP requests |
| `tabs` | Access browser tabs |
| `storage` | Persistent storage |
| `clipboard` | Read/write clipboard |
| `notifications` | Show notifications |
| `dom` | Access page DOM |

### Threat Detection
The sandbox monitors for suspicious behavior:

- Unauthorized API calls
- Excessive network requests
- Credential access attempts
- File system traversal
- Memory scanning

Threat score exceeds threshold → Honeypot redirection

---

## 🔗 Related Projects

- [Marshall Browser](https://github.com/bad-antics/marshall) - OSINT browser
- [NullSec Tools](https://github.com/bad-antics/nullsec-tools) - Security toolkit
- [NullSec Linux](https://github.com/bad-antics/nullsec-linux) - Security distro

---

## ⚠️ Disclaimer

Extensions are for **authorized security testing only**. Obtain proper authorization before testing systems you don't own.

---

<p align="center">
  <b>Part of the NullSec Security Suite</b><br>
  <a href="https://github.com/bad-antics">@bad-antics</a>
</p>
