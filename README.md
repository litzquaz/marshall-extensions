# 🔌 Marshall Extensions

**OSINT & Security Extensions for Marshall Browser**

A collection of installable plugins and extensions that enhance Marshall Browser with additional security testing and reconnaissance capabilities.

## 📦 Available Extensions

### OSINT Extensions
- **🔍 Shodan Lookup** - Query Shodan.io for IP/domain intelligence
- **📋 WHOIS Inspector** - Detailed domain registration info
- **🔐 SSL Certificate Analyzer** - Inspect and analyze SSL/TLS certificates  
- **🌐 DNS Investigator** - DNS records, zone transfers, subdomain enumeration
- **📧 Email Header Analyzer** - Parse and analyze email headers for forensics
- **🖼️ Reverse Image Search** - Search images across multiple engines

### Security Testing Extensions
- **⚡ XSS Scanner** - Detect Cross-Site Scripting vulnerabilities
- **💉 SQLi Detector** - SQL Injection testing toolkit
- **📝 Header Analyzer** - Security header analysis and recommendations
- **🔒 Cookie Inspector** - Cookie security analysis (HttpOnly, Secure, SameSite)
- **🕸️ Web Tech Detector** - Identify frameworks, libraries, and technologies
- **🔗 Link Extractor** - Extract and analyze all links from pages

### Utility Extensions
- **📊 Request Logger** - Log and export all HTTP requests
- **🎨 Response Beautifier** - Format JSON, XML, HTML responses
- **⏱️ Performance Analyzer** - Page load timing and metrics
- **📸 Screenshot Tool** - Full page and element screenshots

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

## 📁 Extension Structure

```
marshall-extensions/
├── osint/
│   ├── shodan-lookup/
│   ├── whois-inspector/
│   ├── ssl-analyzer/
│   ├── dns-investigator/
│   ├── email-headers/
│   └── reverse-image/
├── security/
│   ├── xss-scanner/
│   ├── sqli-detector/
│   ├── header-analyzer/
│   ├── cookie-inspector/
│   ├── webtech-detector/
│   └── link-extractor/
├── utility/
│   ├── request-logger/
│   ├── response-beautifier/
│   ├── performance-analyzer/
│   └── screenshot-tool/
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
