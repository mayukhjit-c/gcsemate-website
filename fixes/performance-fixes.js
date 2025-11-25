/**
 * GCSEMate Performance Fixes
 * Addresses issues P-001 to P-005 from todo.md
 * Priority: Medium-High
 */

(function () {
    'use strict';

    // Debug logging - silent in production
    const DEBUG = false;
    const log = DEBUG ? Function.prototype.bind.call(console.log, console, '⚡ [Perf]') : () => {}; // eslint-disable-line no-console

    /**
     * P-001: Image Lazy Loading
     * Implement native lazy loading for images
     */
    function setupImageLazyLoading() {
        // Add loading="lazy" to all images that don't have it
        document.querySelectorAll('img:not([loading])').forEach(img => {
            // Don't lazy load above-the-fold images
            const rect = img.getBoundingClientRect();
            const isAboveFold = rect.top < window.innerHeight;

            if (!isAboveFold) {
                img.loading = 'lazy';
                img.decoding = 'async';
            }
        });

        // Monitor dynamically added images
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) {
                        const images =
                            node.tagName === 'IMG'
                                ? [node]
                                : node.querySelectorAll?.('img:not([loading])') || [];
                        images.forEach(img => {
                            if (!img.hasAttribute('loading')) {
                                img.loading = 'lazy';
                                img.decoding = 'async';
                            }
                        });
                    }
                });
            });
        });

        observer.observe(document.body, { childList: true, subtree: true });
        log('P-001: Image lazy loading enabled');
    }

    /**
     * P-002: Debounce Scroll and Resize Events
     */
    const EventOptimizer = {
        debounceTimers: new Map(),
        throttleTimers: new Map(),

        // Debounce function
        debounce(func, wait, key) {
            return (...args) => {
                clearTimeout(this.debounceTimers.get(key));
                this.debounceTimers.set(
                    key,
                    setTimeout(() => {
                        func.apply(this, args);
                    }, wait)
                );
            };
        },

        // Throttle function
        throttle(func, limit, key) {
            return (...args) => {
                if (!this.throttleTimers.get(key)) {
                    func.apply(this, args);
                    this.throttleTimers.set(key, true);
                    setTimeout(() => {
                        this.throttleTimers.set(key, false);
                    }, limit);
                }
            };
        },

        // RequestAnimationFrame throttle
        rafThrottle(func) {
            let ticking = false;
            return (...args) => {
                if (!ticking) {
                    requestAnimationFrame(() => {
                        func.apply(this, args);
                        ticking = false;
                    });
                    ticking = true;
                }
            };
        },
    };

    // Optimize scroll handlers - disabled by default as it modifies prototype
    // Enable by calling window.GCSEMatePerformance.optimizeScrollHandlers()
    /* eslint-disable-next-line no-unused-vars */
    /**
     *
     */
    function optimizeScrollHandlers() {
        const originalAddEventListener = EventTarget.prototype.addEventListener;

        EventTarget.prototype.addEventListener = function (type, listener, options) {
            if (type === 'scroll' || type === 'resize') {
                const optimizedListener = EventOptimizer.rafThrottle(listener);
                return originalAddEventListener.call(this, type, optimizedListener, options);
            }
            return originalAddEventListener.call(this, type, listener, options);
        };

        log('P-002: Scroll/resize handlers optimized');
    }

    /**
     * P-003: Resource Preloading
     * Preload critical resources
     */
    function setupResourcePreloading() {
        // Preload critical fonts
        const fonts = [
            'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap',
        ];

        fonts.forEach(font => {
            if (!document.querySelector(`link[href="${font}"]`)) {
                const link = document.createElement('link');
                link.rel = 'preconnect';
                link.href = 'https://fonts.gstatic.com';
                link.crossOrigin = 'anonymous';
                document.head.appendChild(link);
            }
        });

        // Preconnect to external services
        const preconnectUrls = [
            'https://www.googleapis.com',
            'https://firebase.googleapis.com',
            'https://firestore.googleapis.com',
            'https://cdn.jsdelivr.net',
        ];

        preconnectUrls.forEach(url => {
            if (!document.querySelector(`link[rel="preconnect"][href="${url}"]`)) {
                const link = document.createElement('link');
                link.rel = 'preconnect';
                link.href = url;
                link.crossOrigin = 'anonymous';
                document.head.appendChild(link);
            }
        });

        // DNS prefetch for additional domains
        const dnsPrefetchUrls = [
            'https://www.google-analytics.com',
            'https://static.cloudflareinsights.com',
        ];

        dnsPrefetchUrls.forEach(url => {
            if (!document.querySelector(`link[rel="dns-prefetch"][href="${url}"]`)) {
                const link = document.createElement('link');
                link.rel = 'dns-prefetch';
                link.href = url;
                document.head.appendChild(link);
            }
        });

        log('P-003: Resource preloading configured');
    }

    /**
     * P-004: Virtual Scrolling for Large Lists
     */
    class VirtualScroller {
        constructor(container, options = {}) {
            this.container =
                typeof container === 'string' ? document.querySelector(container) : container;

            if (!this.container) {
                return;
            }

            this.options = {
                itemHeight: options.itemHeight || 50,
                buffer: options.buffer || 5,
                renderItem: options.renderItem || (item => `<div>${item}</div>`),
            };

            this.items = [];
            this.scrollTop = 0;
            this.containerHeight = 0;

            this.init();
        }

        init() {
            this.viewport = document.createElement('div');
            this.viewport.className = 'virtual-scroll-viewport';
            this.viewport.style.cssText = `
                position: relative;
                overflow-y: auto;
                height: 100%;
            `;

            this.content = document.createElement('div');
            this.content.className = 'virtual-scroll-content';
            this.content.style.cssText = `
                position: relative;
            `;

            this.viewport.appendChild(this.content);
            this.container.appendChild(this.viewport);

            this.viewport.addEventListener(
                'scroll',
                EventOptimizer.rafThrottle(() => {
                    this.scrollTop = this.viewport.scrollTop;
                    this.render();
                })
            );

            window.addEventListener(
                'resize',
                EventOptimizer.debounce(
                    () => {
                        this.containerHeight = this.viewport.clientHeight;
                        this.render();
                    },
                    150,
                    'virtual-scroll-resize'
                )
            );

            this.containerHeight = this.viewport.clientHeight;
        }

        setItems(items) {
            this.items = items;
            this.content.style.height = `${items.length * this.options.itemHeight}px`;
            this.render();
        }

        render() {
            if (!this.items.length) {
                return;
            }

            const startIndex = Math.max(
                0,
                Math.floor(this.scrollTop / this.options.itemHeight) - this.options.buffer
            );
            const endIndex = Math.min(
                this.items.length,
                Math.ceil((this.scrollTop + this.containerHeight) / this.options.itemHeight) +
                    this.options.buffer
            );

            const fragment = document.createDocumentFragment();

            for (let i = startIndex; i < endIndex; i++) {
                const item = document.createElement('div');
                item.className = 'virtual-scroll-item';
                item.style.cssText = `
                    position: absolute;
                    top: ${i * this.options.itemHeight}px;
                    left: 0;
                    right: 0;
                    height: ${this.options.itemHeight}px;
                `;
                item.innerHTML = this.options.renderItem(this.items[i], i);
                fragment.appendChild(item);
            }

            this.content.innerHTML = '';
            this.content.appendChild(fragment);
        }
    }

    /**
     * P-005: Memory Management
     */
    const MemoryManager = {
        weakMaps: new WeakMap(),
        intervals: new Set(),
        timeouts: new Set(),
        eventListeners: new Map(),

        // Track interval
        setInterval(callback, delay) {
            const id = window.setInterval(callback, delay);
            this.intervals.add(id);
            return id;
        },

        // Clear tracked interval
        clearInterval(id) {
            this.intervals.delete(id);
            window.clearInterval(id);
        },

        // Track timeout
        setTimeout(callback, delay) {
            const id = window.setTimeout(() => {
                this.timeouts.delete(id);
                callback();
            }, delay);
            this.timeouts.add(id);
            return id;
        },

        // Clear tracked timeout
        clearTimeout(id) {
            this.timeouts.delete(id);
            window.clearTimeout(id);
        },

        // Track event listener for later cleanup
        addEventListener(element, type, listener, options) {
            element.addEventListener(type, listener, options);

            if (!this.eventListeners.has(element)) {
                this.eventListeners.set(element, []);
            }
            this.eventListeners.get(element).push({ type, listener, options });
        },

        // Remove all tracked event listeners from element
        removeAllListeners(element) {
            const listeners = this.eventListeners.get(element);
            if (listeners) {
                listeners.forEach(({ type, listener, options }) => {
                    element.removeEventListener(type, listener, options);
                });
                this.eventListeners.delete(element);
            }
        },

        // Cleanup all tracked resources
        cleanup() {
            this.intervals.forEach(id => window.clearInterval(id));
            this.intervals.clear();

            this.timeouts.forEach(id => window.clearTimeout(id));
            this.timeouts.clear();

            this.eventListeners.forEach((listeners, element) => {
                listeners.forEach(({ type, listener, options }) => {
                    element.removeEventListener(type, listener, options);
                });
            });
            this.eventListeners.clear();
        },
    };

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        MemoryManager.cleanup();
    });

    /**
     * Intersection Observer for Efficient Element Tracking
     */
    class IntersectionTracker {
        constructor(options = {}) {
            this.callbacks = new Map();

            this.observer = new IntersectionObserver(
                entries => {
                    entries.forEach(entry => {
                        const callback = this.callbacks.get(entry.target);
                        if (callback) {
                            callback(entry.isIntersecting, entry);
                        }
                    });
                },
                {
                    root: options.root || null,
                    rootMargin: options.rootMargin || '0px',
                    threshold: options.threshold || [0, 0.25, 0.5, 0.75, 1],
                }
            );
        }

        observe(element, callback) {
            this.callbacks.set(element, callback);
            this.observer.observe(element);
        }

        unobserve(element) {
            this.callbacks.delete(element);
            this.observer.unobserve(element);
        }

        disconnect() {
            this.callbacks.clear();
            this.observer.disconnect();
        }
    }

    /**
     * DOM Operation Batching
     */
    const DOMBatcher = {
        readQueue: [],
        writeQueue: [],
        scheduled: false,

        // Schedule a read operation
        read(callback) {
            this.readQueue.push(callback);
            this.schedule();
        },

        // Schedule a write operation
        write(callback) {
            this.writeQueue.push(callback);
            this.schedule();
        },

        // Schedule the batch execution
        schedule() {
            if (this.scheduled) {
                return;
            }
            this.scheduled = true;

            requestAnimationFrame(() => {
                this.flush();
            });
        },

        // Execute all queued operations
        flush() {
            // Execute reads first
            const reads = this.readQueue.slice();
            this.readQueue.length = 0;
            reads.forEach(callback => {
                try {
                    callback();
                } catch (e) {
                    console.error('DOMBatcher read error:', e);
                }
            });

            // Then execute writes
            const writes = this.writeQueue.slice();
            this.writeQueue.length = 0;
            writes.forEach(callback => {
                try {
                    callback();
                } catch (e) {
                    console.error('DOMBatcher write error:', e);
                }
            });

            this.scheduled = false;

            // If more operations were added during flush, schedule again
            if (this.readQueue.length || this.writeQueue.length) {
                this.schedule();
            }
        },
    };

    /**
     * Service Worker Cache Optimization
     */
    function optimizeServiceWorkerCache() {
        if ('serviceWorker' in navigator) {
            // Listen for SW update
            navigator.serviceWorker.ready.then(registration => {
                registration.addEventListener('updatefound', () => {
                    const newWorker = registration.installing;
                    newWorker.addEventListener('statechange', () => {
                        if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                            // New content available, notify user
                            const event = new CustomEvent('swUpdate', {
                                detail: { registration },
                            });
                            window.dispatchEvent(event);
                        }
                    });
                });
            });
        }
    }

    /**
     * Critical CSS Extraction Helper
     * Identifies above-the-fold CSS
     */
    function identifyCriticalCSS() {
        if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
            return;
        }

        // This is a development-only helper
        const aboveFoldElements = [];
        document.querySelectorAll('*').forEach(el => {
            const rect = el.getBoundingClientRect();
            if (rect.top < window.innerHeight && rect.bottom > 0) {
                aboveFoldElements.push(el);
            }
        });

        log(`Above-fold elements: ${aboveFoldElements.length}`);
        log('Run this on page load to identify critical CSS needs');
    }

    // Export for use by other modules
    window.GCSEMatePerformance = {
        EventOptimizer,
        VirtualScroller,
        MemoryManager,
        IntersectionTracker,
        DOMBatcher,
    };

    // Initialize all performance optimizations
    /**
     *
     */
    function init() {
        setupImageLazyLoading();
        // Note: optimizeScrollHandlers modifies addEventListener prototype
        // Enable only if needed: optimizeScrollHandlers();
        setupResourcePreloading();
        optimizeServiceWorkerCache();

        // Development helpers
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            window.identifyCriticalCSS = identifyCriticalCSS;
        }

        log('GCSEMate Performance Fixes Applied');
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
