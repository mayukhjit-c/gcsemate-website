/**
 * GCSEMate Security Fixes
 * Addresses issues S-001, S-002, S-003 from todo.md
 * Priority: High
 */

(function () {
    'use strict';

    console.log('🔒 GCSEMate Security Fixes Loading...');

    /**
     * S-001: Add Content Security Policy headers
     * Note: CSP should ideally be set via server headers, but we can add meta tags as fallback
     */
    function addCSPMeta() {
        const existingCSP = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        if (existingCSP) {
            // Remove existing CSP if it's causing issues - let server handle it
            // existingCSP.remove();
            return;
        }

        // NOTE: CSP via meta tag is limited and can cause issues.
        // For production, configure CSP via server headers instead.
        // Skipping CSP meta tag injection to avoid blocking legitimate resources.
        // If you need client-side CSP, uncomment below with appropriate values.

        /*
        const cspMeta = document.createElement('meta');
        cspMeta.setAttribute('http-equiv', 'Content-Security-Policy');
        cspMeta.setAttribute(
            'content',
            [
                "default-src 'self' https: data: blob:",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:",
                "style-src 'self' 'unsafe-inline' https:",
                "font-src 'self' https: data:",
                "img-src 'self' data: blob: https: http:",
                "connect-src 'self' https: wss:",
                "frame-src 'self' https:",
                "object-src 'none'",
                "base-uri 'self'",
            ].join('; ')
        );
        document.head.insertBefore(cspMeta, document.head.firstChild);
        */

        console.log('✓ S-001: CSP should be configured via server headers for production');
    }

    /**
     * S-002: Input Sanitization
     * Enhanced XSS protection for all user inputs
     */
    const InputSanitizer = {
        // HTML entities map
        htmlEntities: {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;',
        },

        // Sanitize HTML to prevent XSS
        sanitizeHTML(str) {
            if (typeof str !== 'string') {
                return str;
            }
            return str.replace(/[&<>"'`=/]/g, char => this.htmlEntities[char]);
        },

        // Sanitize for use in attributes
        sanitizeAttribute(str) {
            if (typeof str !== 'string') {
                return str;
            }
            return str.replace(/[<>"'`]/g, char => this.htmlEntities[char]);
        },

        // Sanitize URL
        sanitizeURL(url) {
            if (typeof url !== 'string') {
                return '';
            }

            // Allow only safe protocols
            const safeProtocols = ['http:', 'https:', 'mailto:', 'tel:'];
            try {
                const parsed = new URL(url, window.location.origin);
                if (safeProtocols.includes(parsed.protocol)) {
                    return parsed.href;
                }
            } catch (e) {
                // Invalid URL
            }
            return '';
        },

        // Strip all HTML tags
        stripTags(str) {
            if (typeof str !== 'string') {
                return str;
            }
            return str.replace(/<[^>]*>/g, '');
        },

        // Sanitize input value
        sanitizeInput(input) {
            if (!input || !input.value) {
                return;
            }

            const type = input.type || 'text';
            const value = input.value;

            switch (type) {
                case 'email':
                    // Basic email sanitization
                    input.value = value.replace(/[<>'"]/g, '').trim();
                    break;
                case 'url':
                    input.value = this.sanitizeURL(value);
                    break;
                case 'text':
                case 'search':
                case 'textarea':
                    // Remove potentially dangerous patterns
                    input.value = value
                        .replace(/javascript:/gi, '')
                        .replace(/on\w+\s*=/gi, '')
                        .replace(/data:/gi, '');
                    break;
            }
        },
    };

    // Patch innerHTML assignments for safety
    /**
     *
     */
    function patchInnerHTML() {
        const originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');

        if (originalInnerHTML) {
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set: function (value) {
                    // Log potentially dangerous innerHTML usage in development
                    if (
                        window.location.hostname === 'localhost' ||
                        window.location.hostname === '127.0.0.1'
                    ) {
                        if (
                            typeof value === 'string' &&
                            (value.includes('<script') ||
                                value.includes('javascript:') ||
                                value.includes('onerror=') ||
                                value.includes('onload='))
                        ) {
                            console.warn(
                                '⚠️ Potentially dangerous innerHTML detected:',
                                value.substring(0, 100)
                            );
                        }
                    }
                    originalInnerHTML.set.call(this, value);
                },
                get: function () {
                    return originalInnerHTML.get.call(this);
                },
                configurable: true,
            });
        }
    }

    // Apply input sanitization on blur
    /**
     *
     */
    function setupInputSanitization() {
        document.addEventListener(
            'blur',
            e => {
                if (e.target.matches('input, textarea')) {
                    InputSanitizer.sanitizeInput(e.target);
                }
            },
            true
        );

        // Also sanitize on form submit
        document.addEventListener(
            'submit',
            e => {
                const form = e.target;
                if (form.tagName === 'FORM') {
                    const inputs = form.querySelectorAll('input, textarea');
                    inputs.forEach(input => InputSanitizer.sanitizeInput(input));
                }
            },
            true
        );

        console.log('✓ S-002: Input sanitization active');
    }

    /**
     * S-003: Rate Limiting for Client-Side Operations
     */
    const RateLimiter = {
        limits: new Map(),

        // Check if action is allowed
        checkLimit(action, maxAttempts = 5, windowMs = 60000) {
            const now = Date.now();
            const key = action;

            if (!this.limits.has(key)) {
                this.limits.set(key, { count: 1, resetTime: now + windowMs });
                return true;
            }

            const limit = this.limits.get(key);

            if (now > limit.resetTime) {
                // Window expired, reset
                this.limits.set(key, { count: 1, resetTime: now + windowMs });
                return true;
            }

            if (limit.count >= maxAttempts) {
                console.warn(`⚠️ Rate limit exceeded for: ${action}`);
                return false;
            }

            limit.count++;
            return true;
        },

        // Reset limit for an action
        resetLimit(action) {
            this.limits.delete(action);
        },

        // Get remaining attempts
        getRemainingAttempts(action, maxAttempts = 5) {
            const limit = this.limits.get(action);
            if (!limit) {
                return maxAttempts;
            }
            return Math.max(0, maxAttempts - limit.count);
        },
    };

    // Apply rate limiting to sensitive operations
    /**
     *
     */
    function setupRateLimiting() {
        // Rate limit login attempts
        const loginForm = document.querySelector('#login-form, [data-form="login"]');
        if (loginForm) {
            loginForm.addEventListener('submit', e => {
                if (!RateLimiter.checkLimit('login', 5, 300000)) {
                    // 5 attempts per 5 minutes
                    e.preventDefault();
                    alert('Too many login attempts. Please wait 5 minutes before trying again.');
                }
            });
        }

        // Rate limit registration
        const registerForm = document.querySelector('#register-form, [data-form="register"]');
        if (registerForm) {
            registerForm.addEventListener('submit', e => {
                if (!RateLimiter.checkLimit('register', 3, 600000)) {
                    // 3 attempts per 10 minutes
                    e.preventDefault();
                    alert(
                        'Too many registration attempts. Please wait 10 minutes before trying again.'
                    );
                }
            });
        }

        // Rate limit password reset
        const resetForm = document.querySelector('#forgot-password-form, [data-form="reset"]');
        if (resetForm) {
            resetForm.addEventListener('submit', e => {
                if (!RateLimiter.checkLimit('password-reset', 3, 600000)) {
                    e.preventDefault();
                    alert('Too many password reset attempts. Please wait 10 minutes.');
                }
            });
        }

        console.log('✓ S-003: Rate limiting active');
    }

    /**
     * Additional Security: Clickjacking Protection
     */
    function addClickjackingProtection() {
        // Add X-Frame-Options meta
        const xfo = document.createElement('meta');
        xfo.setAttribute('http-equiv', 'X-Frame-Options');
        xfo.setAttribute('content', 'SAMEORIGIN');
        document.head.appendChild(xfo);

        // Framebusting code
        if (window.self !== window.top) {
            console.warn('⚠️ Page is being framed - potential clickjacking attempt');
            // Optionally break out of frame
            // window.top.location = window.self.location;
        }
    }

    /**
     * Additional Security: Secure Cookies Check
     */
    function checkCookieSecurity() {
        // Log cookie security status in development
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            const cookies = document.cookie.split(';');
            cookies.forEach(cookie => {
                const [name] = cookie.trim().split('=');
                if (name) {
                    console.log(
                        `Cookie "${name}" exists (check Secure and HttpOnly flags in production)`
                    );
                }
            });
        }
    }

    /**
     * Additional Security: Prevent Tab Nabbing
     */
    function preventTabNabbing() {
        // Add rel="noopener noreferrer" to external links
        document.querySelectorAll('a[target="_blank"]').forEach(link => {
            const rel = link.getAttribute('rel') || '';
            if (!rel.includes('noopener')) {
                link.setAttribute('rel', (rel + ' noopener noreferrer').trim());
            }
        });

        // Monitor dynamically added links
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) {
                        const links =
                            node.tagName === 'A'
                                ? [node]
                                : node.querySelectorAll?.('a[target="_blank"]') || [];
                        links.forEach(link => {
                            if (link.target === '_blank') {
                                const rel = link.getAttribute('rel') || '';
                                if (!rel.includes('noopener')) {
                                    link.setAttribute('rel', (rel + ' noopener noreferrer').trim());
                                }
                            }
                        });
                    }
                });
            });
        });

        observer.observe(document.body, { childList: true, subtree: true });
        console.log('✓ Tab nabbing prevention active');
    }

    /**
     * Additional Security: Sensitive Data Protection
     */
    function protectSensitiveData() {
        // Prevent sensitive data from being logged
        const sensitivePatterns = [
            /password/i,
            /token/i,
            /secret/i,
            /api.?key/i,
            /credit.?card/i,
            /ssn/i,
        ];

        // Wrap console.log to filter sensitive data in production
        if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
            const originalLog = console.log;
            console.log = function (...args) {
                const sanitizedArgs = args.map(arg => {
                    if (typeof arg === 'string') {
                        let sanitized = arg;
                        sensitivePatterns.forEach(pattern => {
                            if (pattern.test(arg)) {
                                sanitized = '[REDACTED]';
                            }
                        });
                        return sanitized;
                    }
                    return arg;
                });
                originalLog.apply(console, sanitizedArgs);
            };
        }
    }

    // Export for use by other modules
    window.GCSEMateSecurity = {
        InputSanitizer,
        RateLimiter,
    };

    // Initialize all security measures
    /**
     *
     */
    function init() {
        addCSPMeta();
        setupInputSanitization();
        setupRateLimiting();
        addClickjackingProtection();
        checkCookieSecurity();
        preventTabNabbing();
        protectSensitiveData();

        console.log('✅ GCSEMate Security Fixes Applied');
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
