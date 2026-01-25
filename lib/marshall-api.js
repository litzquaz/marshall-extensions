/**
 * Marshall Extension API Library
 * Common utilities and API wrappers for Marshall Browser extensions
 * Part of Marshall Extensions Collection
 */

const marshall = {
    // Tab management
    tabs: {
        async getCurrent() {
            return await window.__marshall__.tabs.getCurrent();
        },
        async create(options) {
            return await window.__marshall__.tabs.create(options);
        },
        async update(tabId, options) {
            return await window.__marshall__.tabs.update(tabId, options);
        },
        onNavigate(callback) {
            window.__marshall__.tabs.onNavigate.addListener(callback);
        }
    },

    // Storage API
    storage: {
        async get(key) {
            return await window.__marshall__.storage.get(key);
        },
        async set(key, value) {
            return await window.__marshall__.storage.set(key, value);
        },
        async remove(key) {
            return await window.__marshall__.storage.remove(key);
        },
        async clear() {
            return await window.__marshall__.storage.clear();
        }
    },

    // Network requests
    network: {
        async fetch(url, options = {}) {
            return await window.__marshall__.network.fetch(url, options);
        },
        async fetchJSON(url, options = {}) {
            const response = await this.fetch(url, options);
            return await response.json();
        }
    },

    // DOM manipulation
    dom: {
        async querySelector(selector) {
            return await window.__marshall__.dom.querySelector(selector);
        },
        async querySelectorAll(selector) {
            return await window.__marshall__.dom.querySelectorAll(selector);
        },
        async getHTML(selector) {
            return await window.__marshall__.dom.getHTML(selector);
        },
        async setHTML(selector, html) {
            return await window.__marshall__.dom.setHTML(selector, html);
        },
        async getText(selector) {
            return await window.__marshall__.dom.getText(selector);
        },
        async setAttribute(selector, attr, value) {
            return await window.__marshall__.dom.setAttribute(selector, attr, value);
        }
    },

    // UI components
    ui: {
        showPanel(html, options = {}) {
            window.__marshall__.ui.showPanel(html, options);
        },
        hidePanel() {
            window.__marshall__.ui.hidePanel();
        },
        notify(message, type = 'info') {
            window.__marshall__.ui.notify(message, type);
        },
        confirm(message) {
            return window.__marshall__.ui.confirm(message);
        },
        prompt(message, defaultValue = '') {
            return window.__marshall__.ui.prompt(message, defaultValue);
        }
    },

    // Context menu
    contextMenu: {
        register(options) {
            window.__marshall__.contextMenu.register(options);
        },
        unregister(id) {
            window.__marshall__.contextMenu.unregister(id);
        }
    },

    // Toolbar
    toolbar: {
        register(options) {
            window.__marshall__.toolbar.register(options);
        },
        unregister(id) {
            window.__marshall__.toolbar.unregister(id);
        },
        setBadge(id, text) {
            window.__marshall__.toolbar.setBadge(id, text);
        }
    },

    // Keyboard shortcuts
    keyboard: {
        register(shortcut, callback) {
            window.__marshall__.keyboard.register(shortcut, callback);
        },
        unregister(shortcut) {
            window.__marshall__.keyboard.unregister(shortcut);
        }
    },

    // Clipboard
    clipboard: {
        async read() {
            return await window.__marshall__.clipboard.read();
        },
        async write(text) {
            return await window.__marshall__.clipboard.write(text);
        }
    },

    // Downloads
    downloads: {
        start(options) {
            window.__marshall__.downloads.start(options);
        }
    },

    // Web requests interception
    webRequest: {
        onBeforeRequest(callback, filter) {
            window.__marshall__.webRequest.onBeforeRequest.addListener(callback, filter);
        },
        onCompleted(callback, filter) {
            window.__marshall__.webRequest.onCompleted.addListener(callback, filter);
        },
        onError(callback, filter) {
            window.__marshall__.webRequest.onError.addListener(callback, filter);
        }
    },

    // Extension lifecycle
    extension: {
        onActivate(callback) {
            window.__marshall__.extension.onActivate = callback;
        },
        onDeactivate(callback) {
            window.__marshall__.extension.onDeactivate = callback;
        },
        export(name, func) {
            window.__marshall__.extension.exports = window.__marshall__.extension.exports || {};
            window.__marshall__.extension.exports[name] = func;
        }
    }
};

// Utility functions
const utils = {
    // URL utilities
    url: {
        parse(url) {
            return new URL(url);
        },
        getDomain(url) {
            return new URL(url).hostname;
        },
        getPath(url) {
            return new URL(url).pathname;
        },
        getParams(url) {
            const params = {};
            new URL(url).searchParams.forEach((v, k) => params[k] = v);
            return params;
        },
        build(base, params) {
            const url = new URL(base);
            for (const [k, v] of Object.entries(params)) {
                url.searchParams.set(k, v);
            }
            return url.toString();
        }
    },

    // String utilities
    string: {
        escapeHtml(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        },
        unescapeHtml(str) {
            const div = document.createElement('div');
            div.innerHTML = str;
            return div.textContent;
        },
        truncate(str, len, suffix = '...') {
            if (str.length <= len) return str;
            return str.substring(0, len - suffix.length) + suffix;
        },
        slugify(str) {
            return str.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
        }
    },

    // Validation utilities
    validate: {
        isIP(str) {
            return /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(str);
        },
        isDomain(str) {
            return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(str);
        },
        isEmail(str) {
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str);
        },
        isURL(str) {
            try {
                new URL(str);
                return true;
            } catch {
                return false;
            }
        }
    },

    // Data utilities
    data: {
        async toJSON(response) {
            return await response.json();
        },
        async toText(response) {
            return await response.text();
        },
        async toBlob(response) {
            return await response.blob();
        },
        base64Encode(str) {
            return btoa(str);
        },
        base64Decode(str) {
            return atob(str);
        }
    },

    // Time utilities
    time: {
        now() {
            return Date.now();
        },
        format(date, format = 'YYYY-MM-DD HH:mm:ss') {
            const d = new Date(date);
            const map = {
                'YYYY': d.getFullYear(),
                'MM': String(d.getMonth() + 1).padStart(2, '0'),
                'DD': String(d.getDate()).padStart(2, '0'),
                'HH': String(d.getHours()).padStart(2, '0'),
                'mm': String(d.getMinutes()).padStart(2, '0'),
                'ss': String(d.getSeconds()).padStart(2, '0')
            };
            return format.replace(/YYYY|MM|DD|HH|mm|ss/g, m => map[m]);
        },
        relative(date) {
            const seconds = Math.floor((Date.now() - new Date(date)) / 1000);
            const intervals = [
                [31536000, 'year'],
                [2592000, 'month'],
                [86400, 'day'],
                [3600, 'hour'],
                [60, 'minute'],
                [1, 'second']
            ];
            for (const [secs, name] of intervals) {
                const count = Math.floor(seconds / secs);
                if (count >= 1) {
                    return `${count} ${name}${count > 1 ? 's' : ''} ago`;
                }
            }
            return 'just now';
        }
    },

    // Cache utilities
    cache: {
        _store: new Map(),
        _timeouts: new Map(),

        set(key, value, ttl = 300000) {
            this._store.set(key, value);
            
            if (this._timeouts.has(key)) {
                clearTimeout(this._timeouts.get(key));
            }
            
            this._timeouts.set(key, setTimeout(() => {
                this._store.delete(key);
                this._timeouts.delete(key);
            }, ttl));
        },

        get(key) {
            return this._store.get(key);
        },

        has(key) {
            return this._store.has(key);
        },

        delete(key) {
            this._store.delete(key);
            if (this._timeouts.has(key)) {
                clearTimeout(this._timeouts.get(key));
                this._timeouts.delete(key);
            }
        },

        clear() {
            this._store.clear();
            this._timeouts.forEach(t => clearTimeout(t));
            this._timeouts.clear();
        }
    }
};

// Export for use in extensions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { marshall, utils };
}
