# 🛠️ Extension Development Guide

Learn how to create your own Marshall Browser extensions.

---

## Quick Start

### 1. Create Extension Directory

```bash
mkdir -p my-extension
cd my-extension
```

### 2. Create Manifest

```json
{
  "name": "my-extension",
  "version": "1.0.0",
  "description": "My awesome extension",
  "main": "main.js",
  "author": "Your Name",
  "permissions": ["network", "storage"],
  "category": "utility",
  "icon": "icon.png"
}
```

### 3. Create Entry Point

```javascript
// main.js
marshall.extension.onActivate(async () => {
  console.log('Extension activated!');
  
  // Register toolbar button
  marshall.toolbar.register({
    id: 'my-button',
    icon: '🔧',
    title: 'My Extension',
    onclick: () => showPanel()
  });
});

function showPanel() {
  marshall.ui.showPanel('<h1>Hello World!</h1>', {
    title: 'My Extension',
    width: 400,
    height: 300
  });
}

marshall.extension.onDeactivate(() => {
  console.log('Extension deactivated');
});
```

### 4. Test Extension

```bash
marshall --load-extension ./my-extension
```

---

## Manifest Reference

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Extension identifier (lowercase, no spaces) |
| `version` | string | Semantic version (1.0.0) |
| `description` | string | Short description |
| `main` | string | Entry point file |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `author` | string | - | Author name |
| `homepage` | string | - | Project URL |
| `repository` | string | - | Source repository |
| `license` | string | MIT | License |
| `icon` | string | - | Icon file path |
| `category` | string | utility | Category (recon, forensics, network, utility) |
| `permissions` | array | [] | Required permissions |
| `minimum_marshall_version` | string | 1.0.0 | Minimum browser version |

### Full Example

```json
{
  "name": "advanced-scanner",
  "version": "2.1.0",
  "description": "Advanced vulnerability scanner for web applications",
  "main": "main.js",
  "author": "NullSec Team",
  "homepage": "https://github.com/bad-antics/advanced-scanner",
  "repository": "https://github.com/bad-antics/advanced-scanner",
  "license": "MIT",
  "icon": "assets/icon.png",
  "category": "recon",
  "permissions": [
    "network",
    "storage",
    "tabs",
    "dom",
    "notifications"
  ],
  "minimum_marshall_version": "2.0.0",
  "sandbox": {
    "security_level": "standard",
    "rate_limits": {
      "requests_per_minute": 100
    }
  }
}
```

---

## Marshall API Reference

### Tabs

```javascript
// Get current tab
const tab = await marshall.tabs.getCurrent();
console.log(tab.url, tab.title);

// Get all tabs
const tabs = await marshall.tabs.getAll();

// Create new tab
const newTab = await marshall.tabs.create({
  url: 'https://example.com',
  active: true
});

// Update tab
await marshall.tabs.update(tab.id, {
  url: 'https://newurl.com'
});

// Close tab
await marshall.tabs.close(tab.id);

// Execute script in tab
const result = await marshall.tabs.executeScript(tab.id, {
  code: 'document.title'
});
```

### Network

```javascript
// Fetch URL
const response = await marshall.network.fetch('https://api.example.com/data', {
  method: 'GET',
  headers: {
    'Authorization': 'Bearer token'
  }
});
const data = await response.json();

// Intercept requests
marshall.webRequest.onBeforeRequest((details) => {
  if (details.url.includes('ads')) {
    return { cancel: true };
  }
  return {};
}, { urls: ['<all_urls>'] });

// Modify headers
marshall.webRequest.onBeforeSendHeaders((details) => {
  details.requestHeaders.push({
    name: 'X-Custom-Header',
    value: 'custom-value'
  });
  return { requestHeaders: details.requestHeaders };
}, { urls: ['<all_urls>'] });
```

### Storage

```javascript
// Set value
await marshall.storage.set('key', 'value');
await marshall.storage.set('config', { theme: 'dark', limit: 100 });

// Get value
const value = await marshall.storage.get('key');
const config = await marshall.storage.get('config');

// Remove value
await marshall.storage.remove('key');

// Clear all
await marshall.storage.clear();

// Get all keys
const keys = await marshall.storage.keys();
```

### UI

```javascript
// Show panel
marshall.ui.showPanel('<div>Content</div>', {
  title: 'Panel Title',
  width: 500,
  height: 400
});

// Show notification
marshall.ui.notify('Operation completed!', 'success');
marshall.ui.notify('Warning message', 'warning');
marshall.ui.notify('Error occurred', 'error');

// Show prompt
const input = await marshall.ui.prompt('Enter value:', 'default');

// Show confirm
const confirmed = await marshall.ui.confirm('Are you sure?');

// Show context menu
marshall.ui.contextMenu([
  { label: 'Option 1', onclick: () => {} },
  { label: 'Option 2', onclick: () => {} },
  { type: 'separator' },
  { label: 'Option 3', onclick: () => {} }
]);
```

### Toolbar

```javascript
// Register button
marshall.toolbar.register({
  id: 'my-button',
  icon: '🔍',
  title: 'My Tool',
  onclick: handleClick
});

// Update button
marshall.toolbar.update('my-button', {
  icon: '✅'
});

// Set badge
marshall.toolbar.setBadge('my-button', '5');

// Remove button
marshall.toolbar.unregister('my-button');
```

### Keyboard

```javascript
// Register shortcut
marshall.keyboard.register('Ctrl+Shift+S', () => {
  console.log('Shortcut triggered!');
});

// Unregister
marshall.keyboard.unregister('Ctrl+Shift+S');
```

### DOM Access

```javascript
// Get page content (requires 'dom' permission)
const html = await marshall.dom.getPageContent();

// Query selector
const elements = await marshall.dom.querySelectorAll('a[href]');

// Get element text
const text = await marshall.dom.getText('h1');

// Click element
await marshall.dom.click('#submit-button');

// Fill input
await marshall.dom.fill('#username', 'test-user');
```

### Clipboard

```javascript
// Read clipboard (requires 'clipboard' permission)
const text = await marshall.clipboard.read();

// Write to clipboard
await marshall.clipboard.write('Copied text');
```

---

## Multi-Language Extensions

### TypeScript

```typescript
// main.ts
import * as marshall from 'marshall-api';

interface ScanResult {
  url: string;
  vulnerabilities: string[];
}

marshall.extension.onActivate(async () => {
  const results: ScanResult[] = await performScan();
  displayResults(results);
});

async function performScan(): Promise<ScanResult[]> {
  const tab = await marshall.tabs.getCurrent();
  // ... scanning logic
  return [];
}
```

Compile with tsconfig.json:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ESNext",
    "outDir": "./dist",
    "strict": true
  }
}
```

### Ruby

```ruby
# main.rb
require 'marshall'

Marshall.extension.on_activate do
  puts "Extension activated!"
  
  Marshall.toolbar.register(
    id: 'cert-check',
    icon: '🔐',
    title: 'Certificate Inspector',
    onclick: -> { inspect_certificate }
  )
end

def inspect_certificate
  tab = Marshall.tabs.get_current
  url = URI.parse(tab['url'])
  
  cert_info = fetch_certificate(url.host)
  display_results(cert_info)
end
```

### Lua

```lua
-- main.lua
local marshall = require("marshall")

marshall.extension.onActivate(function()
  print("[Extension] Activated")
  
  marshall.toolbar.register({
    id = "tamper",
    icon = "🔧",
    title = "Request Tamper",
    onclick = function() show_panel() end
  })
end)

function show_panel()
  local html = generate_panel_html()
  marshall.ui.showPanel(html, {
    title = "Request Tamper",
    width = 600,
    height = 500
  })
end
```

### C Extension

```c
// main.c
#include <marshall_ext.h>

void on_activate() {
    printf("Extension activated\n");
    
    toolbar_button_t btn = {
        .id = "forensics",
        .icon = "🧠",
        .title = "Memory Forensics",
        .onclick = handle_click
    };
    
    marshall_toolbar_register(&btn);
}

void handle_click() {
    // Perform analysis
    analysis_result_t* result = analyze_memory();
    
    char* html = format_results(result);
    marshall_ui_show_panel(html, "Memory Analysis", 700, 600);
    
    free_result(result);
    free(html);
}

MARSHALL_EXTENSION_ENTRY(on_activate, NULL)
```

---

## Best Practices

### Security

1. **Request minimal permissions** - Only what you need
2. **Validate all input** - Don't trust user/external data
3. **Sanitize HTML output** - Prevent XSS in panels
4. **Use HTTPS** - Always for network requests
5. **Don't store secrets** - Use secure credential APIs

### Performance

1. **Lazy load** - Load resources when needed
2. **Cache responses** - Avoid redundant requests
3. **Debounce events** - Don't flood with handlers
4. **Clean up** - Remove listeners on deactivate

### UX

1. **Provide feedback** - Loading states, progress
2. **Handle errors gracefully** - User-friendly messages
3. **Follow conventions** - Consistent UI patterns
4. **Document usage** - Clear README and help

---

## Testing

### Unit Tests

```javascript
// test/main.test.js
const { MockMarshall } = require('marshall-test-utils');

describe('MyExtension', () => {
  let marshall;
  
  beforeEach(() => {
    marshall = new MockMarshall();
  });
  
  it('should register toolbar button', async () => {
    await require('../main.js');
    expect(marshall.toolbar.buttons).toHaveLength(1);
  });
  
  it('should fetch data correctly', async () => {
    marshall.network.mockResponse('https://api.test.com', {
      status: 200,
      body: { data: 'test' }
    });
    
    const result = await fetchData();
    expect(result.data).toBe('test');
  });
});
```

### Integration Tests

```bash
# Run extension in test mode
marshall --test-extension ./my-extension

# Run automated tests
marshall --run-extension-tests ./my-extension/tests
```

---

## Publishing

### 1. Prepare for Release

```bash
# Update version in manifest.json
# Update CHANGELOG.md
# Run tests
npm test
```

### 2. Sign Extension

```bash
# Generate key pair (first time only)
marshall-sign --generate-key

# Sign extension
marshall-sign --extension ./my-extension --output my-extension.signed.zip
```

### 3. Submit for Review

1. Fork marshall-extensions repository
2. Add extension to `extensions/category/`
3. Open pull request
4. Wait for review

### 4. Distribution

After approval:
- Listed in Marshall extension catalog
- Installable via `marshall://extensions`
- Available via CLI: `marshall --install my-extension`
