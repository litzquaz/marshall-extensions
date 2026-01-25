/**
 * Shodan Lookup Extension for Marshall Browser
 * Query Shodan.io for IP/domain intelligence
 * Part of Marshall Extensions Collection
 */

class ShodanLookup {
    constructor() {
        this.apiKey = null;
        this.baseUrl = 'https://api.shodan.io';
        this.cache = new Map();
        this.cacheTimeout = 300000; // 5 minutes
    }

    async init() {
        // Load API key from storage
        this.apiKey = await marshall.storage.get('shodan_api_key');
        
        if (!this.apiKey) {
            marshall.ui.notify('Please configure your Shodan API key in settings', 'warning');
            return false;
        }

        // Register context menu
        marshall.contextMenu.register({
            id: 'shodan-lookup',
            title: 'Lookup in Shodan',
            contexts: ['selection', 'link'],
            onclick: (info) => this.contextMenuHandler(info)
        });

        // Register keyboard shortcut
        marshall.keyboard.register('Ctrl+Shift+S', () => this.lookupCurrentPage());

        // Auto lookup on page load if enabled
        const autoLookup = await marshall.storage.get('shodan_auto_lookup');
        if (autoLookup) {
            marshall.tabs.onNavigate((tab) => this.autoLookupHandler(tab));
        }

        console.log('[Shodan Lookup] Extension initialized');
        return true;
    }

    async lookupIP(ip) {
        // Check cache
        const cached = this.cache.get(ip);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        try {
            const response = await marshall.network.fetch(
                `${this.baseUrl}/shodan/host/${ip}?key=${this.apiKey}`
            );

            if (!response.ok) {
                if (response.status === 404) {
                    return { error: 'No information available for this IP' };
                }
                throw new Error(`Shodan API error: ${response.status}`);
            }

            const data = await response.json();
            
            // Cache result
            this.cache.set(ip, { data, timestamp: Date.now() });
            
            return data;
        } catch (error) {
            console.error('[Shodan Lookup] Error:', error);
            return { error: error.message };
        }
    }

    async lookupDomain(domain) {
        try {
            const response = await marshall.network.fetch(
                `${this.baseUrl}/dns/domain/${domain}?key=${this.apiKey}`
            );

            if (!response.ok) {
                throw new Error(`Shodan API error: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('[Shodan Lookup] Error:', error);
            return { error: error.message };
        }
    }

    async search(query) {
        try {
            const response = await marshall.network.fetch(
                `${this.baseUrl}/shodan/host/search?key=${this.apiKey}&query=${encodeURIComponent(query)}`
            );

            if (!response.ok) {
                throw new Error(`Shodan API error: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('[Shodan Lookup] Error:', error);
            return { error: error.message };
        }
    }

    formatResult(data) {
        if (data.error) {
            return `<div class="shodan-error">${data.error}</div>`;
        }

        const html = `
            <div class="shodan-result">
                <div class="shodan-header">
                    <h2>${data.ip_str || 'Unknown IP'}</h2>
                    <span class="shodan-org">${data.org || 'N/A'}</span>
                </div>
                
                <div class="shodan-section">
                    <h3>📍 Location</h3>
                    <table>
                        <tr><td>Country:</td><td>${data.country_name || 'N/A'} ${data.country_code || ''}</td></tr>
                        <tr><td>City:</td><td>${data.city || 'N/A'}</td></tr>
                        <tr><td>ISP:</td><td>${data.isp || 'N/A'}</td></tr>
                        <tr><td>ASN:</td><td>${data.asn || 'N/A'}</td></tr>
                    </table>
                </div>

                <div class="shodan-section">
                    <h3>🔓 Open Ports</h3>
                    <div class="shodan-ports">
                        ${(data.ports || []).map(p => `<span class="port-badge">${p}</span>`).join('')}
                    </div>
                </div>

                <div class="shodan-section">
                    <h3>🏷️ Hostnames</h3>
                    <ul>
                        ${(data.hostnames || []).map(h => `<li>${h}</li>`).join('') || '<li>None found</li>'}
                    </ul>
                </div>

                <div class="shodan-section">
                    <h3>⚠️ Vulnerabilities</h3>
                    <div class="shodan-vulns">
                        ${(data.vulns || []).map(v => `<span class="vuln-badge">${v}</span>`).join('') || 'None detected'}
                    </div>
                </div>

                ${data.data ? `
                <div class="shodan-section">
                    <h3>🔍 Services</h3>
                    ${data.data.slice(0, 5).map(service => `
                        <div class="shodan-service">
                            <strong>Port ${service.port}/${service.transport || 'tcp'}</strong>
                            <span>${service.product || ''} ${service.version || ''}</span>
                            <pre>${(service.data || '').substring(0, 200)}...</pre>
                        </div>
                    `).join('')}
                </div>
                ` : ''}

                <div class="shodan-footer">
                    <small>Last updated: ${data.last_update || 'Unknown'}</small>
                    <a href="https://www.shodan.io/host/${data.ip_str}" target="_blank">View on Shodan →</a>
                </div>
            </div>
        `;

        return html;
    }

    async lookupCurrentPage() {
        const tab = await marshall.tabs.getCurrent();
        const url = new URL(tab.url);
        const hostname = url.hostname;

        // Check if it's an IP address
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        
        marshall.ui.showPanel('<div class="shodan-loading">🔍 Looking up...</div>');

        let result;
        if (ipRegex.test(hostname)) {
            result = await this.lookupIP(hostname);
        } else {
            // Resolve domain to IP first
            const dnsResult = await this.lookupDomain(hostname);
            if (dnsResult.data && dnsResult.data.length > 0) {
                const ip = dnsResult.data[0].value;
                result = await this.lookupIP(ip);
            } else {
                result = { error: 'Could not resolve domain to IP' };
            }
        }

        marshall.ui.showPanel(this.formatResult(result), {
            title: `Shodan: ${hostname}`,
            width: 500,
            height: 600
        });
    }

    async contextMenuHandler(info) {
        const target = info.selectionText || info.linkUrl;
        
        if (!target) {
            marshall.ui.notify('No IP or domain selected', 'error');
            return;
        }

        // Extract IP or domain from selection
        const ipRegex = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/;
        const domainRegex = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/;

        const ipMatch = target.match(ipRegex);
        const domainMatch = target.match(domainRegex);

        marshall.ui.showPanel('<div class="shodan-loading">🔍 Looking up...</div>');

        let result;
        if (ipMatch) {
            result = await this.lookupIP(ipMatch[0]);
        } else if (domainMatch) {
            const dnsResult = await this.lookupDomain(domainMatch[0]);
            if (dnsResult.data && dnsResult.data.length > 0) {
                result = await this.lookupIP(dnsResult.data[0].value);
            } else {
                result = { error: 'Could not resolve domain' };
            }
        } else {
            result = { error: 'No valid IP or domain found in selection' };
        }

        marshall.ui.showPanel(this.formatResult(result));
    }

    async autoLookupHandler(tab) {
        // Don't auto-lookup local pages
        if (tab.url.startsWith('file://') || tab.url.startsWith('marshall://')) {
            return;
        }

        const url = new URL(tab.url);
        const hostname = url.hostname;

        // Skip localhost and private IPs
        if (hostname === 'localhost' || hostname.startsWith('192.168.') || 
            hostname.startsWith('10.') || hostname.startsWith('127.')) {
            return;
        }

        const result = await this.lookupIP(hostname);
        
        if (!result.error && result.vulns && result.vulns.length > 0) {
            marshall.ui.notify(
                `⚠️ ${result.vulns.length} vulnerabilities detected on this host`,
                'warning'
            );
        }
    }
}

// Extension entry point
const shodanLookup = new ShodanLookup();

marshall.extension.onActivate(async () => {
    await shodanLookup.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Shodan Lookup] Extension deactivated');
});

// Export for API access
marshall.extension.export('lookup', (target) => shodanLookup.lookupIP(target));
marshall.extension.export('search', (query) => shodanLookup.search(query));
