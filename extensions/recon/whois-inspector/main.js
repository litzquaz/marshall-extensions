/**
 * WHOIS Inspector Extension for Marshall Browser
 * Detailed domain registration lookup and analysis
 * Part of Marshall Extensions Collection
 */

class WhoisInspector {
    constructor() {
        this.apiEndpoints = [
            'https://whois.arin.net/rest/ip/',
            'https://rdap.org/domain/',
        ];
        this.cache = new Map();
        this.cacheTimeout = 600000; // 10 minutes
    }

    async init() {
        // Register context menu
        marshall.contextMenu.register({
            id: 'whois-lookup',
            title: 'WHOIS Lookup',
            contexts: ['selection', 'link'],
            onclick: (info) => this.contextMenuHandler(info)
        });

        // Register toolbar button
        marshall.toolbar.register({
            id: 'whois-inspector',
            icon: '📋',
            title: 'WHOIS Inspector',
            onclick: () => this.lookupCurrentDomain()
        });

        // Register keyboard shortcut
        marshall.keyboard.register('Ctrl+Shift+W', () => this.lookupCurrentDomain());

        console.log('[WHOIS Inspector] Extension initialized');
        return true;
    }

    async lookupDomain(domain) {
        // Clean domain
        domain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].toLowerCase();

        // Check cache
        const cached = this.cache.get(domain);
        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            return cached.data;
        }

        try {
            // Try RDAP first (modern WHOIS replacement)
            const rdapResult = await this.queryRDAP(domain);
            if (rdapResult && !rdapResult.error) {
                this.cache.set(domain, { data: rdapResult, timestamp: Date.now() });
                return rdapResult;
            }

            // Fallback to traditional WHOIS API
            const whoisResult = await this.queryWhoisAPI(domain);
            this.cache.set(domain, { data: whoisResult, timestamp: Date.now() });
            return whoisResult;

        } catch (error) {
            console.error('[WHOIS Inspector] Error:', error);
            return { error: error.message, domain: domain };
        }
    }

    async queryRDAP(domain) {
        try {
            const response = await marshall.network.fetch(
                `https://rdap.org/domain/${domain}`,
                { headers: { 'Accept': 'application/json' } }
            );

            if (!response.ok) {
                return null;
            }

            const data = await response.json();
            return this.parseRDAPResponse(data, domain);
        } catch (error) {
            return null;
        }
    }

    async queryWhoisAPI(domain) {
        // Use a public WHOIS API
        try {
            const response = await marshall.network.fetch(
                `https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=${domain}&outputFormat=JSON`
            );

            if (!response.ok) {
                throw new Error('WHOIS API error');
            }

            const data = await response.json();
            return this.parseWhoisResponse(data, domain);
        } catch (error) {
            // Return basic info if API fails
            return {
                domain: domain,
                status: 'Lookup failed',
                error: 'Unable to retrieve WHOIS information. Try again later.',
                timestamp: new Date().toISOString()
            };
        }
    }

    parseRDAPResponse(data, domain) {
        const result = {
            domain: domain,
            source: 'RDAP',
            timestamp: new Date().toISOString()
        };

        // Handle
        result.handle = data.handle || 'N/A';

        // Status
        result.status = data.status || [];

        // Events (registration dates)
        if (data.events) {
            for (const event of data.events) {
                if (event.eventAction === 'registration') {
                    result.createdDate = event.eventDate;
                }
                if (event.eventAction === 'expiration') {
                    result.expiresDate = event.eventDate;
                }
                if (event.eventAction === 'last changed') {
                    result.updatedDate = event.eventDate;
                }
            }
        }

        // Nameservers
        if (data.nameservers) {
            result.nameservers = data.nameservers.map(ns => ns.ldhName || ns.handle);
        }

        // Entities (registrar, registrant, etc.)
        result.entities = {};
        if (data.entities) {
            for (const entity of data.entities) {
                const roles = entity.roles || [];
                const vcardArray = entity.vcardArray?.[1] || [];
                
                const entityInfo = {
                    handle: entity.handle,
                    roles: roles
                };

                // Parse vCard
                for (const item of vcardArray) {
                    if (item[0] === 'fn') {
                        entityInfo.name = item[3];
                    }
                    if (item[0] === 'email') {
                        entityInfo.email = item[3];
                    }
                    if (item[0] === 'tel') {
                        entityInfo.phone = item[3];
                    }
                    if (item[0] === 'adr') {
                        entityInfo.address = item[3]?.filter(a => a).join(', ');
                    }
                }

                for (const role of roles) {
                    result.entities[role] = entityInfo;
                }
            }
        }

        // Links
        if (data.links) {
            result.links = data.links.map(l => ({ rel: l.rel, href: l.href }));
        }

        return result;
    }

    parseWhoisResponse(data, domain) {
        const record = data.WhoisRecord || {};
        
        return {
            domain: domain,
            source: 'WHOIS',
            timestamp: new Date().toISOString(),
            registrar: record.registrarName,
            createdDate: record.createdDate,
            updatedDate: record.updatedDate,
            expiresDate: record.expiresDate,
            status: record.status?.split(' ') || [],
            nameservers: record.nameServers?.hostNames || [],
            entities: {
                registrant: record.registrant || {},
                admin: record.administrativeContact || {},
                tech: record.technicalContact || {}
            },
            rawText: record.rawText
        };
    }

    async lookupCurrentDomain() {
        const tab = await marshall.tabs.getCurrent();
        const url = new URL(tab.url);
        const domain = url.hostname;

        marshall.ui.showPanel('<div class="loading">🔍 Looking up WHOIS...</div>');

        const result = await this.lookupDomain(domain);
        this.showResults(result);
    }

    async contextMenuHandler(info) {
        const target = info.selectionText || info.linkUrl;
        
        if (!target) {
            marshall.ui.notify('No domain selected', 'error');
            return;
        }

        // Extract domain from selection
        const domainRegex = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/;
        const match = target.match(domainRegex);

        if (!match) {
            marshall.ui.notify('No valid domain found', 'error');
            return;
        }

        marshall.ui.showPanel('<div class="loading">🔍 Looking up WHOIS...</div>');

        const result = await this.lookupDomain(match[0]);
        this.showResults(result);
    }

    showResults(data) {
        if (data.error) {
            marshall.ui.showPanel(`
                <div class="whois-error">
                    <h3>❌ Lookup Failed</h3>
                    <p>${data.error}</p>
                    <p>Domain: ${data.domain}</p>
                </div>
            `);
            return;
        }

        const formatDate = (dateStr) => {
            if (!dateStr) return 'N/A';
            try {
                return new Date(dateStr).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                });
            } catch {
                return dateStr;
            }
        };

        const getDaysUntilExpiry = (expiryDate) => {
            if (!expiryDate) return null;
            const days = Math.ceil((new Date(expiryDate) - new Date()) / (1000 * 60 * 60 * 24));
            return days;
        };

        const daysUntilExpiry = getDaysUntilExpiry(data.expiresDate);
        const expiryClass = daysUntilExpiry && daysUntilExpiry < 30 ? 'expiring-soon' : '';

        const html = `
            <div class="whois-result">
                <div class="whois-header">
                    <h2>📋 ${data.domain}</h2>
                    <span class="source">${data.source}</span>
                </div>

                <div class="whois-section">
                    <h3>📅 Registration Dates</h3>
                    <table>
                        <tr>
                            <td>Created:</td>
                            <td>${formatDate(data.createdDate)}</td>
                        </tr>
                        <tr>
                            <td>Updated:</td>
                            <td>${formatDate(data.updatedDate)}</td>
                        </tr>
                        <tr class="${expiryClass}">
                            <td>Expires:</td>
                            <td>
                                ${formatDate(data.expiresDate)}
                                ${daysUntilExpiry ? `<span class="days">(${daysUntilExpiry} days)</span>` : ''}
                            </td>
                        </tr>
                    </table>
                </div>

                ${data.registrar ? `
                <div class="whois-section">
                    <h3>🏢 Registrar</h3>
                    <p>${data.registrar}</p>
                </div>
                ` : ''}

                <div class="whois-section">
                    <h3>🔒 Status</h3>
                    <div class="status-badges">
                        ${(data.status || []).map(s => `<span class="status-badge">${s}</span>`).join('')}
                    </div>
                </div>

                ${data.nameservers && data.nameservers.length > 0 ? `
                <div class="whois-section">
                    <h3>🌐 Nameservers</h3>
                    <ul>
                        ${data.nameservers.map(ns => `<li>${ns}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}

                ${Object.keys(data.entities || {}).length > 0 ? `
                <div class="whois-section">
                    <h3>👤 Contacts</h3>
                    ${Object.entries(data.entities).map(([role, entity]) => `
                        <div class="contact-card">
                            <h4>${role.charAt(0).toUpperCase() + role.slice(1)}</h4>
                            ${entity.name ? `<p><strong>Name:</strong> ${entity.name}</p>` : ''}
                            ${entity.email ? `<p><strong>Email:</strong> ${entity.email}</p>` : ''}
                            ${entity.phone ? `<p><strong>Phone:</strong> ${entity.phone}</p>` : ''}
                            ${entity.address ? `<p><strong>Address:</strong> ${entity.address}</p>` : ''}
                            ${entity.organization ? `<p><strong>Org:</strong> ${entity.organization}</p>` : ''}
                        </div>
                    `).join('')}
                </div>
                ` : ''}

                <div class="whois-footer">
                    <small>Queried: ${data.timestamp}</small>
                </div>

                <div class="whois-actions">
                    <button onclick="whoisInspector.copyResults()">Copy Results</button>
                    <button onclick="whoisInspector.exportJSON()">Export JSON</button>
                    <button onclick="whoisInspector.openExternal('${data.domain}')">View on ICANN</button>
                </div>
            </div>
        `;

        marshall.ui.showPanel(html, {
            title: `WHOIS: ${data.domain}`,
            width: 500,
            height: 600
        });

        // Store for export
        this.lastResult = data;
    }

    copyResults() {
        if (!this.lastResult) return;

        const text = `
WHOIS Results for ${this.lastResult.domain}
==========================================
Created: ${this.lastResult.createdDate || 'N/A'}
Updated: ${this.lastResult.updatedDate || 'N/A'}
Expires: ${this.lastResult.expiresDate || 'N/A'}
Registrar: ${this.lastResult.registrar || 'N/A'}
Nameservers: ${(this.lastResult.nameservers || []).join(', ')}
Status: ${(this.lastResult.status || []).join(', ')}
        `.trim();

        marshall.clipboard.write(text);
        marshall.ui.notify('WHOIS results copied to clipboard', 'success');
    }

    exportJSON() {
        if (!this.lastResult) return;

        const blob = new Blob([JSON.stringify(this.lastResult, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        marshall.downloads.start({
            url: url,
            filename: `whois-${this.lastResult.domain}-${Date.now()}.json`
        });
    }

    openExternal(domain) {
        marshall.tabs.create({
            url: `https://lookup.icann.org/lookup?name=${domain}`
        });
    }
}

// Extension entry point
const whoisInspector = new WhoisInspector();

marshall.extension.onActivate(async () => {
    await whoisInspector.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[WHOIS Inspector] Extension deactivated');
});

// Export for API access
marshall.extension.export('lookup', (domain) => whoisInspector.lookupDomain(domain));
