/**
 * GCSEMate - Compatibility & Display Fixes
 * Fixes for cross-browser compatibility and mobile issues
 * Load this script early to catch any display problems
 */

(function () {
    'use strict';

    // Dev-only logger: logs only on localhost or dev/staging hosts
    const DEBUG_ENABLED = (typeof window !== 'undefined' && window.location && (window.location.hostname === 'localhost' || /(^|\.)dev\.|staging/.test(window.location.hostname)));
    function debugLog(...args) { if (DEBUG_ENABLED) { console.log(...args); } }

    // ═══════════════════════════════════════════════════════════════
    // SECTION 1: Browser Detection & Compatibility
    // ═══════════════════════════════════════════════════════════════

    const BrowserCompat = {
        // Detect browser and add appropriate classes
        init() {
            const ua = navigator.userAgent;
            const html = document.documentElement;

            // Browser detection
            const browsers = {
                'is-chrome': /Chrome/.test(ua) && !/Edge|Edg/.test(ua),
                'is-firefox': /Firefox/.test(ua),
                'is-safari': /Safari/.test(ua) && !/Chrome/.test(ua),
                'is-edge': /Edge|Edg/.test(ua),
                'is-ie': /Trident|MSIE/.test(ua),
                'is-opera': /Opera|OPR/.test(ua),
            };

            Object.entries(browsers).forEach(([cls, match]) => {
                if (match) {
                    html.classList.add(cls);
                }
            });

            // OS detection
            const os = {
                'is-windows': /Windows/.test(ua),
                'is-mac': /Mac/.test(ua),
                'is-ios': /iPhone|iPad|iPod/.test(ua),
                'is-android': /Android/.test(ua),
                'is-linux': /Linux/.test(ua) && !/Android/.test(ua),
            };

            Object.entries(os).forEach(([cls, match]) => {
                if (match) {
                    html.classList.add(cls);
                }
            });

            // Device type
            if (/Mobi|Android/i.test(ua)) {
                html.classList.add('is-mobile');
            } else if (/Tablet|iPad/i.test(ua)) {
                html.classList.add('is-tablet');
            } else {
                html.classList.add('is-desktop');
            }

            // Feature detection
            this.detectFeatures();
        },

        detectFeatures() {
            const html = document.documentElement;

            const canCSSSupports =
                typeof window.CSS !== 'undefined' &&
                typeof window.CSS.supports === 'function';

            // Backdrop filter support
            if (
                !canCSSSupports ||
                (!CSS.supports('backdrop-filter', 'blur(10px)') &&
                    !CSS.supports('-webkit-backdrop-filter', 'blur(10px)'))
            ) {
                html.classList.add('no-backdrop-filter');
            }

            // CSS Grid support
            if (!canCSSSupports || !CSS.supports('display', 'grid')) {
                html.classList.add('no-grid');
            }

            // CSS Variables support
            if (!canCSSSupports || !CSS.supports('color', 'var(--test)')) {
                html.classList.add('no-css-vars');
            }

            // Touch support
            if ('ontouchstart' in window || navigator.maxTouchPoints > 0) {
                html.classList.add('has-touch');
            }

            // Reduced motion preference
            if (
                typeof window.matchMedia === 'function' &&
                window.matchMedia('(prefers-reduced-motion: reduce)').matches
            ) {
                html.classList.add('reduced-motion');
            }
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 2: Display Fix - Ensure Content Shows
    // ═══════════════════════════════════════════════════════════════

    const DisplayFix = {
        init() {
            const run = () => {
                if (!document.body) {
                    return;
                }

                // Ensure body is visible
                document.body.style.visibility = 'visible';
                document.body.style.opacity = '1';

                // Force repaint on problematic browsers
                this.forceRepaint();

                // Fix loading overlay timeout
                this.fixLoadingOverlay();

                // Handle visibility change
                document.addEventListener('visibilitychange', () => {
                    if (!document.hidden) {
                        this.forceRepaint();
                    }
                });
            };

            // If this script is loaded in <head>, body may not exist yet
            if (!document.body) {
                document.addEventListener('DOMContentLoaded', run, { once: true });
                return;
            }

            run();
        },

        forceRepaint() {
            // Force a browser repaint to fix rendering issues
            if (!document.body) {
                return;
            }

            requestAnimationFrame(() => {
                if (!document.body) {
                    return;
                }
                const originalDisplay = document.body.style.display;
                document.body.style.display = 'none';
                // Trigger reflow
                void document.body.offsetHeight;
                document.body.style.display = originalDisplay;
            });
        },

        fixLoadingOverlay() {
            // Maximum time for loading overlay (safety net)
            const maxLoadTime = 8000; // 8 seconds max

            setTimeout(() => {
                const overlay = document.getElementById('loading-overlay');
                if (overlay && overlay.style.display !== 'none') {
                    console.warn('Loading overlay timeout - forcing hide');
                    overlay.style.opacity = '0';
                    overlay.style.pointerEvents = 'none';
                    setTimeout(() => {
                        overlay.style.display = 'none';
                    }, 300);
                }
            }, maxLoadTime);
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 3: Mobile Menu Fix
    // ═══════════════════════════════════════════════════════════════

    const MobileMenuFix = {
        init() {
            // Wait for DOM to be ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => this.setup());
            } else {
                this.setup();
            }
        },

        setup() {
            const toggle = document.getElementById('mobile-menu-toggle');
            const menu = document.getElementById('mobile-menu');

            if (!toggle || !menu) {
                return;
            }

            // Ensure proper initial state
            menu.classList.add('hidden');
            menu.setAttribute('aria-hidden', 'true');

            // Fix toggle functionality
            toggle.addEventListener('click', e => {
                e.preventDefault();
                e.stopPropagation();
                this.toggleMenu(menu);
            });

            // Close on escape key
            document.addEventListener('keydown', e => {
                if (e.key === 'Escape' && !menu.classList.contains('hidden')) {
                    this.closeMenu(menu);
                }
            });

            // Close on outside click
            menu.addEventListener('click', e => {
                if (e.target === menu) {
                    this.closeMenu(menu);
                }
            });

            // Close menu when nav link is clicked
            menu.querySelectorAll('a').forEach(link => {
                link.addEventListener('click', () => {
                    this.closeMenu(menu);
                });
            });

            // Handle resize
            window.addEventListener('resize', () => {
                if (window.innerWidth > 768 && !menu.classList.contains('hidden')) {
                    this.closeMenu(menu);
                }
            });
        },

        toggleMenu(menu) {
            if (menu.classList.contains('hidden')) {
                this.openMenu(menu);
            } else {
                this.closeMenu(menu);
            }
        },

        openMenu(menu) {
            menu.classList.remove('hidden');
            menu.setAttribute('aria-hidden', 'false');
            document.body.style.overflow = 'hidden';

            // Focus first link for accessibility
            const firstLink = menu.querySelector('a');
            if (firstLink) {
                firstLink.focus();
            }
        },

        closeMenu(menu) {
            menu.classList.add('hidden');
            menu.setAttribute('aria-hidden', 'true');
            document.body.style.overflow = '';
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 4: Viewport Height Fix for Mobile
    // ═══════════════════════════════════════════════════════════════

    const ViewportFix = {
        init() {
            this.setViewportHeight();

            // Update on resize (debounced)
            let resizeTimer;
            window.addEventListener('resize', () => {
                clearTimeout(resizeTimer);
                resizeTimer = setTimeout(() => this.setViewportHeight(), 100);
            });

            // Update on orientation change
            window.addEventListener('orientationchange', () => {
                setTimeout(() => this.setViewportHeight(), 100);
            });
        },

        setViewportHeight() {
            // Fix for mobile browsers where 100vh includes the URL bar
            const vh = window.innerHeight * 0.01;
            document.documentElement.style.setProperty('--vh', `${vh}px`);
            document.documentElement.style.setProperty(
                '--viewport-height',
                `${window.innerHeight}px`
            );
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 5: Image Loading Fix
    // ═══════════════════════════════════════════════════════════════

    const ImageFix = {
        init() {
            // Add loading="lazy" to images that don't have it
            document.querySelectorAll('img:not([loading])').forEach(img => {
                img.loading = 'lazy';
            });

            // Handle broken images
            document.addEventListener(
                'error',
                e => {
                    if (e.target.tagName === 'IMG') {
                        this.handleBrokenImage(e.target);
                    }
                },
                true
            );
        },

        handleBrokenImage(img) {
            // Replace with placeholder or hide
            img.style.opacity = '0.3';
            img.alt = img.alt || 'Image unavailable';
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 6: Font Loading Fix
    // ═══════════════════════════════════════════════════════════════

    const FontFix = {
        init() {
            // Check if fonts are loaded
            if (document.fonts && document.fonts.ready) {
                document.fonts.ready.then(() => {
                    document.documentElement.classList.add('fonts-loaded');
                });
            } else {
                // Fallback for browsers without Font Loading API
                setTimeout(() => {
                    document.documentElement.classList.add('fonts-loaded');
                }, 1000);
            }

            // FontAwesome fallback check
            this.checkFontAwesome();
        },

        checkFontAwesome() {
            setTimeout(() => {
                const testIcon = document.createElement('i');
                testIcon.className = 'fas fa-check';
                testIcon.style.cssText = 'position:absolute;visibility:hidden;';
                document.body.appendChild(testIcon);

                const computed = window.getComputedStyle(testIcon);
                const fontFamily = computed.fontFamily;

                if (!fontFamily.includes('Font Awesome')) {
                    console.warn('FontAwesome may not be loaded properly');
                    document.documentElement.classList.add('no-fontawesome');
                }

                document.body.removeChild(testIcon);
            }, 2000);
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 7: Form Fix for Mobile
    // ═══════════════════════════════════════════════════════════════

    const FormFix = {
        init() {
            // Prevent iOS zoom on input focus
            document.querySelectorAll('input, select, textarea').forEach(el => {
                const fontSize = window.getComputedStyle(el).fontSize;
                if (parseInt(fontSize) < 16) {
                    el.style.fontSize = '16px';
                }
            });

            // Fix autofill styling issues
            this.fixAutofill();
        },

        fixAutofill() {
            const style = document.createElement('style');
            style.textContent = `
                input:-webkit-autofill,
                input:-webkit-autofill:hover,
                input:-webkit-autofill:focus,
                textarea:-webkit-autofill,
                select:-webkit-autofill {
                    -webkit-text-fill-color: inherit !important;
                    -webkit-box-shadow: 0 0 0 1000px white inset !important;
                    box-shadow: 0 0 0 1000px white inset !important;
                    transition: background-color 5000s ease-in-out 0s;
                }
            `;
            document.head.appendChild(style);
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 8: Error Handler (Improved)
    // ═══════════════════════════════════════════════════════════════

    const ErrorFix = {
        init() {
            // Catch unhandled errors
            window.addEventListener('error', e => {
                console.error('Caught error:', e.message);
                // Don't let script errors break the page
                if (e.target && e.target.tagName === 'SCRIPT') {
                    console.warn('Script failed to load:', e.target.src);
                }
            });

            // Catch unhandled promise rejections
            window.addEventListener('unhandledrejection', e => {
                console.error('Unhandled promise rejection:', e.reason);

                // Avoid swallowing real errors; only suppress known benign browser issues
                const msg =
                    (typeof e.reason === 'string' && e.reason) ||
                    (e.reason && (e.reason.message || e.reason.toString())) ||
                    '';
                if (
                    /ResizeObserver loop limit exceeded/i.test(msg) ||
                    /ResizeObserver loop completed with undelivered notifications/i.test(msg)
                ) {
                    e.preventDefault();
                }
            });
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 9: Performance Optimization
    // ═══════════════════════════════════════════════════════════════

    const PerformanceFix = {
        init() {
            // Reduce animations on slow devices
            this.checkDevicePerformance();

            // Defer non-critical resources
            this.deferNonCritical();
        },

        checkDevicePerformance() {
            // Check if device might be slow
            if (navigator.hardwareConcurrency && navigator.hardwareConcurrency < 4) {
                document.documentElement.classList.add('low-performance');
            }

            // Check connection speed
            if (navigator.connection) {
                const conn = navigator.connection;
                if (conn.effectiveType === 'slow-2g' || conn.effectiveType === '2g') {
                    document.documentElement.classList.add('slow-connection');
                }
            }
        },

        deferNonCritical() {
            // Defer animations until user interacts
            const enableAnimations = () => {
                document.documentElement.classList.add('animations-enabled');
                window.removeEventListener('scroll', enableAnimations);
                window.removeEventListener('click', enableAnimations);
                window.removeEventListener('touchstart', enableAnimations);
            };

            window.addEventListener('scroll', enableAnimations, { once: true, passive: true });
            window.addEventListener('click', enableAnimations, { once: true });
            window.addEventListener('touchstart', enableAnimations, { once: true, passive: true });
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 10: Scroll Fix
    // ═══════════════════════════════════════════════════════════════

    const ScrollFix = {
        init() {
            // Smooth scroll for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', e => {
                    const targetId = anchor.getAttribute('href');
                    if (targetId === '#') {
                        return;
                    }

                    const target = document.querySelector(targetId);
                    if (target) {
                        e.preventDefault();
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start',
                        });
                    }
                });
            });

            // Fix scroll position on hash change
            if (window.location.hash) {
                setTimeout(() => {
                    const target = document.querySelector(window.location.hash);
                    if (target) {
                        target.scrollIntoView({ block: 'start' });
                    }
                }, 100);
            }
        },
    };

    // ═══════════════════════════════════════════════════════════════
    // SECTION 11: Initialize All Fixes
    // ═══════════════════════════════════════════════════════════════

    /**
     *
     */
    function initAllFixes() {
        try {
            BrowserCompat.init();
            DisplayFix.init();
            ViewportFix.init();
            ErrorFix.init();
            PerformanceFix.init();

            // Wait for DOM
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', initDOMFixes);
            } else {
                initDOMFixes();
            }
        } catch (err) {
            console.error('Error initializing fixes:', err);
        }
    }

    /**
     *
     */
    function initDOMFixes() {
        try {
            MobileMenuFix.init();
            ImageFix.init();
            FontFix.init();
            FormFix.init();
            ScrollFix.init();

            debugLog('✓ GCSEMate compatibility fixes loaded');
        } catch (err) {
            console.error('Error initializing DOM fixes:', err);
        }
    }

    // Initialize immediately
    initAllFixes();

    // ═══════════════════════════════════════════════════════════════
    // SECTION 12: Polyfills for Older Browsers
    // ═══════════════════════════════════════════════════════════════

    // CustomEvent polyfill for IE
    if (typeof window.CustomEvent !== 'function') {
        window.CustomEvent = function (event, params) {
            params = params || { bubbles: false, cancelable: false, detail: null };
            const evt = document.createEvent('CustomEvent');
            evt.initCustomEvent(event, params.bubbles, params.cancelable, params.detail);
            return evt;
        };
    }

    // Element.matches polyfill
    if (!Element.prototype.matches) {
        Element.prototype.matches =
            Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector;
    }

    // Element.closest polyfill
    if (!Element.prototype.closest) {
        Element.prototype.closest = function (s) {
            let el = this;
            do {
                if (Element.prototype.matches.call(el, s)) {
                    return el;
                }
                el = el.parentElement || el.parentNode;
            } while (el !== null && el.nodeType === 1);
            return null;
        };
    }
})();
