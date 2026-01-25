/**
 * Header Analyzer Extension for Marshall Browser
 * Analyze HTTP security headers and provide recommendations
 * Part of Marshall Extensions Collection
 */

class HeaderAnalyzer {
    constructor() {
        this.securityHeaders = {
            'content-security-policy': {
                name: 'Content-Security-Policy',
                importance: 'Critical',
                description: 'Prevents XSS and data injection attacks',
                recommendation: "Add CSP header: Content-Security-Policy: default-src 'self'"
            },
            'x-content-type-options': {
                name: 'X-Content-Type-Options',
                importance: 'High',
                description: 'Prevents MIME-type sniffing',
                recommendation: 'Add header: X-Content-Type-Options: nosniff',
                expectedValue: 'nosniff'
            },
            'x-frame-options': {
                name: 'X-Frame-Options',
                importance: 'High',
                description: 'Prevents clickjacking attacks',
                recommendation: 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
            },
            'x-xss-protection': {
                name: 'X-XSS-Protection',
                importance: 'Medium',
                description: 'Enables browser XSS filtering (legacy)',
                recommendation: 'Add header: X-XSS-Protection: 1; mode=block',
                note: 'Deprecated in modern browsers, CSP is preferred'
            },
            'strict-transport-security': {
                name: 'Strict-Transport-Security',
                importance: 'Critical',
                description: 'Enforces HTTPS connections',
                recommendation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
            },
            'referrer-policy': {
                name: 'Referrer-Policy',
                importance: 'Medium',
                description: 'Controls referrer information leakage',
                recommendation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
            },
            'permissions-policy': {
                name: 'Permissions-Policy',
                importance: 'Medium',
                description: 'Controls browser feature permissions',
                recommendation: "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()"
            },
            'x-permitted-cross-domain-policies': {
                name: 'X-Permitted-Cross-Domain-Policies',
                importance: 'Low',
                description: 'Controls cross-domain policy files',
                recommendation: 'Add header: X-Permitted-Cross-Domain-Policies: none'
            },
            'cross-origin-embedder-policy': {
                name: 'Cross-Origin-Embedder-Policy',
                importance: 'Medium',
                description: 'Prevents loading cross-origin resources',
                recommendation: 'Add header: Cross-Origin-Embedder-Policy: require-corp'
            },
            'cross-origin-opener-policy': {
                name: 'Cross-Origin-Opener-Policy',
                importance: 'Medium',
                description: 'Isolates browsing context',
                recommendation: 'Add header: Cross-Origin-Opener-Policy: same-origin'
            },
            'cross-origin-resource-policy': {
                name: 'Cross-Origin-Resource-Policy',
                importance: 'Medium',
                description: 'Prevents cross-origin reads',
                recommendation: 'Add header: Cross-Origin-Resource-Policy: same-origin'
            }
        };

        this.dangerousHeaders = {
            'server': {
                name: 'Server',
                risk: 'Information Disclosure',
                description: 'Reveals web server software and version'
            },
            'x-powered-by': {
                name: 'X-Powered-By',
                risk: 'Information Disclosure',
                description: 'Reveals backend technology stack'
            },
            'x-aspnet-version': {
                name: 'X-AspNet-Version',
                risk: 'Information Disclosure',
                description: 'Reveals ASP.NET version'
            },
            'x-aspnetmvc-version': {
                name: 'X-AspNetMvc-Version',
                risk: 'Information Disclosure',
                description: 'Reveals ASP.NET MVC version'
            }
        };

        this.lastAnalysis = null;
    }

    async init() {
        // Register toolbar button
        marshall.toolbar.register({
            id: 'header-analyzer',
            icon: '📝',
            title: 'Header Analyzer',
            onclick: () => this.analyze()
        });

        // Register keyboard shortcut
        marshall.keyboard.register('Ctrl+Shift+H', () => this.analyze());

        // Intercept responses for automatic analysis
        marshall.webRequest.onCompleted((details) => {
            if (details.type === 'main_frame') {
                this.analyzeHeaders(details.responseHeaders, details.url);
            }
        });

        console.log('[Header Analyzer] Extension initialized');
        return true;
    }

    async analyze() {
        const tab = await marshall.tabs.getCurrent();
        
        marshall.ui.showPanel('<div class="loading">🔍 Analyzing headers...</div>');

        try {
            const response = await marshall.network.fetch(tab.url, {
                method: 'HEAD',
                credentials: 'include'
            });

            const headers = {};
            response.headers.forEach((value, key) => {
                headers[key.toLowerCase()] = value;
            });

            const analysis = this.analyzeHeaders(headers, tab.url);
            this.showResults(analysis, tab.url);

        } catch (error) {
            marshall.ui.notify('Error analyzing headers: ' + error.message, 'error');
        }
    }

    analyzeHeaders(headers, url) {
        const analysis = {
            url: url,
            timestamp: new Date().toISOString(),
            score: 100,
            grade: 'A+',
            present: [],
            missing: [],
            dangerous: [],
            recommendations: [],
            allHeaders: headers
        };

        // Check security headers
        for (const [headerKey, headerInfo] of Object.entries(this.securityHeaders)) {
            const value = headers[headerKey];
            
            if (value) {
                const headerAnalysis = {
                    ...headerInfo,
                    value: value,
                    status: 'present'
                };

                // Check for weak configurations
                if (headerKey === 'content-security-policy') {
                    headerAnalysis.issues = this.analyzeCSP(value);
                    if (headerAnalysis.issues.length > 0) {
                        headerAnalysis.status = 'weak';
                    }
                }

                if (headerKey === 'strict-transport-security') {
                    headerAnalysis.issues = this.analyzeHSTS(value);
                    if (headerAnalysis.issues.length > 0) {
                        headerAnalysis.status = 'weak';
                    }
                }

                analysis.present.push(headerAnalysis);
            } else {
                analysis.missing.push(headerInfo);
                
                // Deduct points based on importance
                if (headerInfo.importance === 'Critical') {
                    analysis.score -= 15;
                } else if (headerInfo.importance === 'High') {
                    analysis.score -= 10;
                } else if (headerInfo.importance === 'Medium') {
                    analysis.score -= 5;
                }

                analysis.recommendations.push(headerInfo.recommendation);
            }
        }

        // Check for dangerous headers
        for (const [headerKey, headerInfo] of Object.entries(this.dangerousHeaders)) {
            const value = headers[headerKey];
            
            if (value) {
                analysis.dangerous.push({
                    ...headerInfo,
                    value: value
                });
                analysis.score -= 5;
                analysis.recommendations.push(`Remove or mask the ${headerInfo.name} header`);
            }
        }

        // Calculate grade
        analysis.score = Math.max(0, analysis.score);
        analysis.grade = this.calculateGrade(analysis.score);

        this.lastAnalysis = analysis;
        return analysis;
    }

    analyzeCSP(value) {
        const issues = [];
        
        if (value.includes("'unsafe-inline'")) {
            issues.push("Uses 'unsafe-inline' which reduces XSS protection");
        }
        if (value.includes("'unsafe-eval'")) {
            issues.push("Uses 'unsafe-eval' which allows code execution");
        }
        if (value.includes('*')) {
            issues.push("Uses wildcard (*) which is too permissive");
        }
        if (!value.includes('default-src')) {
            issues.push("Missing default-src directive");
        }
        if (value.includes('http:')) {
            issues.push("Allows insecure HTTP sources");
        }

        return issues;
    }

    analyzeHSTS(value) {
        const issues = [];
        
        const maxAgeMatch = value.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
            const maxAge = parseInt(maxAgeMatch[1]);
            if (maxAge < 31536000) {
                issues.push(`max-age is ${maxAge} seconds (recommended: at least 31536000)`);
            }
        } else {
            issues.push("Missing max-age directive");
        }

        if (!value.includes('includeSubDomains')) {
            issues.push("Missing includeSubDomains directive");
        }

        return issues;
    }

    calculateGrade(score) {
        if (score >= 90) return 'A+';
        if (score >= 80) return 'A';
        if (score >= 70) return 'B';
        if (score >= 60) return 'C';
        if (score >= 50) return 'D';
        return 'F';
    }

    showResults(analysis, url) {
        const gradeColors = {
            'A+': '#00ff00',
            'A': '#44ff00',
            'B': '#88ff00',
            'C': '#ffff00',
            'D': '#ff8800',
            'F': '#ff0000'
        };

        const html = `
            <div class="header-analysis">
                <div class="analysis-header">
                    <h2>Security Headers Analysis</h2>
                    <div class="score-badge" style="background: ${gradeColors[analysis.grade]}">
                        <span class="grade">${analysis.grade}</span>
                        <span class="score">${analysis.score}/100</span>
                    </div>
                </div>
                
                <p class="url">${analysis.url}</p>

                <div class="analysis-section">
                    <h3>✅ Present Headers (${analysis.present.length})</h3>
                    ${analysis.present.length > 0 ? `
                        <ul class="header-list present">
                            ${analysis.present.map(h => `
                                <li class="${h.status}">
                                    <strong>${h.name}</strong>
                                    <span class="importance ${h.importance.toLowerCase()}">${h.importance}</span>
                                    <code>${this.truncate(h.value, 60)}</code>
                                    ${h.issues && h.issues.length > 0 ? `
                                        <ul class="issues">
                                            ${h.issues.map(i => `<li>⚠️ ${i}</li>`).join('')}
                                        </ul>
                                    ` : ''}
                                </li>
                            `).join('')}
                        </ul>
                    ` : '<p>No security headers present</p>'}
                </div>

                <div class="analysis-section">
                    <h3>❌ Missing Headers (${analysis.missing.length})</h3>
                    ${analysis.missing.length > 0 ? `
                        <ul class="header-list missing">
                            ${analysis.missing.map(h => `
                                <li>
                                    <strong>${h.name}</strong>
                                    <span class="importance ${h.importance.toLowerCase()}">${h.importance}</span>
                                    <p>${h.description}</p>
                                </li>
                            `).join('')}
                        </ul>
                    ` : '<p>All recommended headers are present! 🎉</p>'}
                </div>

                ${analysis.dangerous.length > 0 ? `
                <div class="analysis-section">
                    <h3>⚠️ Information Disclosure (${analysis.dangerous.length})</h3>
                    <ul class="header-list dangerous">
                        ${analysis.dangerous.map(h => `
                            <li>
                                <strong>${h.name}</strong>: <code>${h.value}</code>
                                <p>${h.description}</p>
                            </li>
                        `).join('')}
                    </ul>
                </div>
                ` : ''}

                ${analysis.recommendations.length > 0 ? `
                <div class="analysis-section">
                    <h3>📋 Recommendations</h3>
                    <ol class="recommendations">
                        ${analysis.recommendations.map(r => `<li>${r}</li>`).join('')}
                    </ol>
                </div>
                ` : ''}

                <div class="analysis-actions">
                    <button onclick="headerAnalyzer.showAllHeaders()">View All Headers</button>
                    <button onclick="headerAnalyzer.exportReport()">Export Report</button>
                    <button onclick="headerAnalyzer.copyRecommendations()">Copy Headers</button>
                </div>
            </div>
        `;

        marshall.ui.showPanel(html, {
            title: 'Header Analyzer',
            width: 550,
            height: 700
        });
    }

    truncate(str, len) {
        if (str.length <= len) return str;
        return str.substring(0, len) + '...';
    }

    showAllHeaders() {
        if (!this.lastAnalysis) return;

        const headers = this.lastAnalysis.allHeaders;
        const html = `
            <div class="all-headers">
                <h3>All Response Headers</h3>
                <table>
                    <thead>
                        <tr><th>Header</th><th>Value</th></tr>
                    </thead>
                    <tbody>
                        ${Object.entries(headers).map(([k, v]) => `
                            <tr>
                                <td><strong>${k}</strong></td>
                                <td><code>${v}</code></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
                <button onclick="headerAnalyzer.showResults(headerAnalyzer.lastAnalysis, headerAnalyzer.lastAnalysis.url)">
                    Back to Analysis
                </button>
            </div>
        `;

        marshall.ui.showPanel(html);
    }

    exportReport() {
        if (!this.lastAnalysis) return;

        const report = {
            ...this.lastAnalysis,
            generatedBy: 'Marshall Header Analyzer Extension',
            version: '1.0.0'
        };

        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        marshall.downloads.start({
            url: url,
            filename: `header-analysis-${Date.now()}.json`
        });
    }

    copyRecommendations() {
        if (!this.lastAnalysis) return;

        const headers = [];
        for (const missing of this.lastAnalysis.missing) {
            headers.push(missing.recommendation.replace('Add header: ', ''));
        }

        marshall.clipboard.write(headers.join('\n'));
        marshall.ui.notify('Recommended headers copied to clipboard', 'success');
    }
}

// Extension entry point
const headerAnalyzer = new HeaderAnalyzer();

marshall.extension.onActivate(async () => {
    await headerAnalyzer.init();
});

marshall.extension.onDeactivate(() => {
    console.log('[Header Analyzer] Extension deactivated');
});

// Export for API access
marshall.extension.export('analyze', () => headerAnalyzer.analyze());
marshall.extension.export('getAnalysis', () => headerAnalyzer.lastAnalysis);
