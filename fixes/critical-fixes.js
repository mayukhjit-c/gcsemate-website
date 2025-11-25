/**
 * GCSEMate - Critical Bug Fixes
 * Addresses: CB-001 to CB-005, M-001 to M-005
 * Priority: CRITICAL (🔴)
 */

(function () {
    'use strict';

    console.log('🔴 Loading Critical Fixes...');

    // ================================================
    // CONFIGURATION
    // ================================================
    const CONFIG = {
        DOWNLOAD_RATE_LIMIT: 3,
        RATE_LIMIT_WINDOW_MS: 60000,
        DEBOUNCE_DELAY_MS: 300,
        TOAST_DURATION_MS: 3000,
        MODAL_ANIMATION_MS: 250,
        AUTH_MAX_ATTEMPTS: 5,
        AUTH_LOCKOUT_DURATION_MS: 300000, // 5 minutes
    };

    // ================================================
    // CB-001 & CB-002: MODAL CLOSE FIXES
    // Universal modal system with ESC key and click outside support
    // ================================================

    const modalStack = [];
    let scrollbarWidth = 0;

    // Calculate scrollbar width once
    function getScrollbarWidth() {
        if (scrollbarWidth > 0) return scrollbarWidth;
        const outer = document.createElement('div');
        outer.style.cssText =
            'visibility:hidden;overflow:scroll;position:absolute;top:-9999px;width:100px;';
        document.body.appendChild(outer);
        scrollbarWidth = outer.offsetWidth - outer.clientWidth;
        document.body.removeChild(outer);
        return scrollbarWidth;
    }

    // Lock body scroll when modal opens
    function lockBodyScroll() {
        const scrollY = window.scrollY;
        document.body.style.overflow = 'hidden';
        document.body.style.paddingRight = `${getScrollbarWidth()}px`;
        document.body.style.position = 'fixed';
        document.body.style.top = `-${scrollY}px`;
        document.body.style.width = '100%';
        document.body.dataset.scrollY = scrollY;
        document.body.classList.add('modal-open');
    }

    // Unlock body scroll when modal closes
    function unlockBodyScroll() {
        if (modalStack.length > 0) return; // Don't unlock if other modals are open

        const scrollY = document.body.dataset.scrollY || 0;
        document.body.style.overflow = '';
        document.body.style.paddingRight = '';
        document.body.style.position = '';
        document.body.style.top = '';
        document.body.style.width = '';
        document.body.classList.remove('modal-open');
        window.scrollTo(0, parseInt(scrollY));
    }

    // Enhanced modal open with proper animations and accessibility
    window.safeOpenModal = function (modalId, contentCallback) {
        const modal = document.getElementById(modalId);
        if (!modal) {
            console.warn(`Modal ${modalId} not found`);
            return false;
        }

        // Prevent duplicate opens
        if (modalStack.includes(modalId)) return false;

        // Load content first if callback provided
        if (contentCallback && typeof contentCallback === 'function') {
            try {
                contentCallback(modal);
            } catch (error) {
                console.error('Error loading modal content:', error);
            }
        }

        // Add to stack
        modalStack.push(modalId);

        // Lock scroll
        lockBodyScroll();

        // Setup the modal
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('data-close-on-esc', 'true');
        modal.setAttribute('data-close-on-backdrop', 'true');

        // Initial state for animation
        modal.style.opacity = '0';

        const modalContent = modal.querySelector('.modal-content, > div:not(.fixed)');
        if (modalContent) {
            modalContent.style.transform = 'scale(0.95) translateY(-10px)';
            modalContent.style.transition = `transform ${CONFIG.MODAL_ANIMATION_MS}ms cubic-bezier(0.34, 1.56, 0.64, 1), opacity ${CONFIG.MODAL_ANIMATION_MS}ms ease-out`;
        }

        // Animate in
        requestAnimationFrame(() => {
            modal.style.transition = `opacity ${CONFIG.MODAL_ANIMATION_MS}ms ease-out`;
            modal.style.opacity = '1';

            if (modalContent) {
                modalContent.style.transform = 'scale(1) translateY(0)';
            }
        });

        // Focus first focusable element
        setTimeout(() => {
            const focusable = modal.querySelector(
                'button, [href], input:not([type="hidden"]), select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            if (focusable) {
                focusable.focus();
            }
        }, CONFIG.MODAL_ANIMATION_MS);

        // Store the element that triggered the modal
        modal.dataset.triggeredBy = document.activeElement?.id || '';

        return true;
    };

    // Enhanced modal close with animations
    window.safeCloseModal = function (modalId) {
        const modal = typeof modalId === 'string' ? document.getElementById(modalId) : modalId;
        if (!modal) return false;

        const id = modal.id;

        // Remove from stack
        const stackIndex = modalStack.indexOf(id);
        if (stackIndex > -1) {
            modalStack.splice(stackIndex, 1);
        }

        // Animate out
        modal.style.transition = `opacity ${CONFIG.MODAL_ANIMATION_MS}ms ease-out`;
        modal.style.opacity = '0';

        const modalContent = modal.querySelector('.modal-content, > div:not(.fixed)');
        if (modalContent) {
            modalContent.style.transform = 'scale(0.95) translateY(-10px)';
        }

        setTimeout(() => {
            modal.classList.add('hidden');
            modal.style.display = 'none';
            modal.style.opacity = '';
            modal.style.transition = '';

            if (modalContent) {
                modalContent.style.transform = '';
                modalContent.style.transition = '';
            }

            // Restore focus to trigger element
            const triggerId = modal.dataset.triggeredBy;
            if (triggerId) {
                const trigger = document.getElementById(triggerId);
                if (trigger) trigger.focus();
            }

            // Unlock scroll if no more modals
            unlockBodyScroll();
        }, CONFIG.MODAL_ANIMATION_MS);

        return true;
    };

    // Close topmost modal
    window.closeTopmostModal = function () {
        if (modalStack.length === 0) return false;
        const topModalId = modalStack[modalStack.length - 1];
        return window.safeCloseModal(topModalId);
    };

    // Universal ESC key handler for all modals
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' || e.keyCode === 27) {
            // Find all visible modals with close-on-esc enabled
            const visibleModals = document.querySelectorAll(
                '.fixed:not(.hidden)[data-close-on-esc="true"], .fixed[style*="display: flex"][data-close-on-esc="true"], .fixed[style*="display: block"][data-close-on-esc="true"]'
            );

            if (visibleModals.length > 0) {
                e.preventDefault();
                const topModal = visibleModals[visibleModals.length - 1];

                if (topModal.id) {
                    window.safeCloseModal(topModal.id);
                } else {
                    // For dynamically created modals without IDs
                    topModal.style.opacity = '0';
                    setTimeout(() => topModal.remove(), CONFIG.MODAL_ANIMATION_MS);
                }
            }
        }
    });

    // Universal click outside to close handler
    document.addEventListener('click', function (e) {
        const target = e.target;

        // Check if clicked on modal backdrop (the outer fixed container)
        if (
            target.classList.contains('fixed') &&
            (target.classList.contains('inset-0') ||
                target.hasAttribute('data-close-on-backdrop')) &&
            target.getAttribute('data-close-on-backdrop') !== 'false'
        ) {
            // Make sure we clicked on the backdrop, not the content
            const isBackdrop =
                e.target === target && !e.target.closest('.modal-content, [role="dialog"] > div');

            if (isBackdrop) {
                e.preventDefault();
                if (target.id) {
                    window.safeCloseModal(target.id);
                } else {
                    target.style.opacity = '0';
                    setTimeout(() => target.remove(), CONFIG.MODAL_ANIMATION_MS);
                }
            }
        }
    });

    // ================================================
    // CB-003: FIREBASE OPERATIONS ERROR HANDLING
    // ================================================

    window.safeFirebaseOperation = async function (operation, errorMessage = 'Operation failed') {
        try {
            return await operation();
        } catch (error) {
            console.error('Firebase operation error:', error);

            // Map Firebase error codes to user-friendly messages
            const errorMessages = {
                'permission-denied': "You don't have permission to perform this action.",
                unavailable: 'Service temporarily unavailable. Please try again.',
                cancelled: 'Operation was cancelled.',
                unknown: 'An unexpected error occurred.',
                'invalid-argument': 'Invalid data provided.',
                'not-found': 'The requested resource was not found.',
                'already-exists': 'This resource already exists.',
                'resource-exhausted': 'Too many requests. Please wait a moment.',
                'failed-precondition': 'Operation cannot be performed in current state.',
                aborted: 'Operation was aborted.',
                'out-of-range': 'Operation out of valid range.',
                unimplemented: 'Operation not implemented.',
                internal: 'Internal error occurred.',
                'data-loss': 'Data loss occurred.',
                unauthenticated: 'You need to be logged in to perform this action.',
            };

            const friendlyMessage = errorMessages[error.code] || errorMessage;

            if (typeof showToast === 'function') {
                showToast(friendlyMessage, 'error');
            }

            throw error;
        }
    };

    // ================================================
    // CB-004: PREVENT DOUBLE FORM SUBMISSION
    // ================================================

    const submittingForms = new Set();

    window.preventDoubleSubmit = function (formOrButton, asyncOperation) {
        const element =
            typeof formOrButton === 'string' ? document.getElementById(formOrButton) : formOrButton;

        if (!element) return Promise.reject(new Error('Element not found'));

        const id = element.id || element.name || 'form';

        if (submittingForms.has(id)) {
            return Promise.reject(new Error('Form is already being submitted'));
        }

        submittingForms.add(id);

        // Find submit button
        const button =
            element.tagName === 'BUTTON'
                ? element
                : element.querySelector('button[type="submit"], button:not([type])');
        let originalContent = '';

        if (button) {
            originalContent = button.innerHTML;
            button.disabled = true;
            button.innerHTML =
                '<span class="loader inline-block w-4 h-4 mr-2"></span> Processing...';
            button.classList.add('opacity-75', 'cursor-not-allowed');
        }

        return asyncOperation().finally(() => {
            submittingForms.delete(id);

            if (button) {
                button.disabled = false;
                button.innerHTML = originalContent;
                button.classList.remove('opacity-75', 'cursor-not-allowed');
            }
        });
    };

    // Auto-prevent double submit on all forms
    document.addEventListener('submit', function (e) {
        const form = e.target;
        if (form.dataset.preventDoubleSubmit === 'false') return;

        const submitBtn = form.querySelector('button[type="submit"], button:not([type])');
        if (submitBtn && !submitBtn.disabled) {
            // Already handled by custom handlers, just track
            const formId = form.id || 'form-' + Date.now();
            if (submittingForms.has(formId)) {
                e.preventDefault();
                return false;
            }
        }
    });

    // ================================================
    // CB-005: MEMORY LEAK PREVENTION - Listener Registry
    // ================================================

    class ListenerRegistry {
        constructor() {
            this.listeners = new Map();
            this.unsubscribers = new Set();
        }

        registerFirestoreListener(name, unsubscribeFn) {
            // Clean up existing listener with same name
            this.unregisterFirestoreListener(name);

            this.listeners.set(name, unsubscribeFn);
            this.unsubscribers.add(unsubscribeFn);

            console.log(`Registered listener: ${name}`);
        }

        unregisterFirestoreListener(name) {
            const unsubscribe = this.listeners.get(name);
            if (unsubscribe && typeof unsubscribe === 'function') {
                try {
                    unsubscribe();
                    console.log(`Unregistered listener: ${name}`);
                } catch (error) {
                    console.warn(`Error unregistering listener ${name}:`, error);
                }
            }
            this.listeners.delete(name);
            this.unsubscribers.delete(unsubscribe);
        }

        cleanupAll() {
            console.log(`Cleaning up ${this.listeners.size} listeners...`);

            this.listeners.forEach((unsubscribe, name) => {
                try {
                    if (typeof unsubscribe === 'function') {
                        unsubscribe();
                    }
                } catch (error) {
                    console.warn(`Error cleaning up listener ${name}:`, error);
                }
            });

            this.listeners.clear();
            this.unsubscribers.clear();

            console.log('All listeners cleaned up');
        }

        getActiveListeners() {
            return Array.from(this.listeners.keys());
        }
    }

    window.listenerRegistry = new ListenerRegistry();

    // Cleanup on page unload
    window.addEventListener('beforeunload', function () {
        window.listenerRegistry.cleanupAll();
    });

    // Cleanup on visibility change (when user switches tabs for long time)
    let hiddenTime = null;
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) {
            hiddenTime = Date.now();
        } else if (hiddenTime && Date.now() - hiddenTime > 30 * 60 * 1000) {
            // If hidden for more than 30 minutes, cleanup and refresh
            console.log('Page was hidden for long time, refreshing listeners...');
            // Could trigger refresh here if needed
        }
    });

    // ================================================
    // S-002: AUTH RATE LIMITING
    // ================================================

    const authAttempts = new Map();

    window.checkAuthRateLimit = function (identifier) {
        const now = Date.now();
        const attempts = authAttempts.get(identifier) || [];

        // Filter to only recent attempts within the lockout window
        const recentAttempts = attempts.filter(t => now - t < CONFIG.AUTH_LOCKOUT_DURATION_MS);

        if (recentAttempts.length >= CONFIG.AUTH_MAX_ATTEMPTS) {
            const oldestAttempt = Math.min(...recentAttempts);
            const remainingLockout = CONFIG.AUTH_LOCKOUT_DURATION_MS - (now - oldestAttempt);
            const remainingMinutes = Math.ceil(remainingLockout / 60000);

            return {
                allowed: false,
                message: `Too many attempts. Please try again in ${remainingMinutes} minute${remainingMinutes > 1 ? 's' : ''}.`,
                remainingTime: remainingLockout,
            };
        }

        return {
            allowed: true,
            attemptsRemaining: CONFIG.AUTH_MAX_ATTEMPTS - recentAttempts.length,
        };
    };

    window.recordAuthAttempt = function (identifier) {
        const attempts = authAttempts.get(identifier) || [];
        attempts.push(Date.now());

        // Keep only recent attempts to prevent memory bloat
        const now = Date.now();
        const recentAttempts = attempts.filter(t => now - t < CONFIG.AUTH_LOCKOUT_DURATION_MS);

        authAttempts.set(identifier, recentAttempts);
    };

    window.clearAuthAttempts = function (identifier) {
        authAttempts.delete(identifier);
    };

    // ================================================
    // A-002: FOCUS TRAP FOR MODALS
    // ================================================

    const FOCUSABLE_SELECTORS = [
        'button:not([disabled])',
        '[href]',
        'input:not([disabled]):not([type="hidden"])',
        'select:not([disabled])',
        'textarea:not([disabled])',
        '[tabindex]:not([tabindex="-1"])',
    ].join(', ');

    function trapFocus(modal) {
        const focusableElements = modal.querySelectorAll(FOCUSABLE_SELECTORS);
        const firstFocusable = focusableElements[0];
        const lastFocusable = focusableElements[focusableElements.length - 1];

        if (!firstFocusable) return;

        function handleTabKey(e) {
            if (e.key !== 'Tab') return;

            if (e.shiftKey) {
                if (document.activeElement === firstFocusable) {
                    e.preventDefault();
                    lastFocusable.focus();
                }
            } else {
                if (document.activeElement === lastFocusable) {
                    e.preventDefault();
                    firstFocusable.focus();
                }
            }
        }

        modal.addEventListener('keydown', handleTabKey);

        // Store cleanup function
        modal._focusTrapCleanup = () => {
            modal.removeEventListener('keydown', handleTabKey);
        };
    }

    // Auto-apply focus trap to modals when they open
    const modalObserver = new MutationObserver(function (mutations) {
        mutations.forEach(mutation => {
            mutation.addedNodes.forEach(node => {
                if (
                    node.nodeType === 1 &&
                    (node.classList?.contains('fixed') || node.getAttribute?.('role') === 'dialog')
                ) {
                    trapFocus(node);
                }
            });
        });
    });

    modalObserver.observe(document.body, { childList: true, subtree: true });

    // ================================================
    // UTILITY: Enhanced debounce and throttle
    // ================================================

    window.debounce = function (func, wait = CONFIG.DEBOUNCE_DELAY_MS) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func.apply(this, args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    };

    window.throttle = function (func, limit = 100) {
        let inThrottle;
        return function (...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => (inThrottle = false), limit);
            }
        };
    };

    // ================================================
    // Apply close buttons to existing modals
    // ================================================

    function ensureModalCloseButton(modal) {
        // Check if modal already has a close button
        if (modal.querySelector('[data-modal-close]')) return;

        // Find the modal content container
        const content = modal.querySelector('.modal-content, > div:first-child, > div.bg-white');
        if (!content) return;

        // Check if there's already a close button
        const existingClose = content.querySelector(
            'button[onclick*="close"], .close-btn, [aria-label*="close"]'
        );
        if (existingClose) {
            existingClose.setAttribute('data-modal-close', 'true');
            return;
        }

        // Add a close button
        const closeBtn = document.createElement('button');
        closeBtn.setAttribute('data-modal-close', 'true');
        closeBtn.setAttribute('aria-label', 'Close modal');
        closeBtn.className =
            'absolute top-4 right-4 w-8 h-8 flex items-center justify-center rounded-full bg-gray-100 hover:bg-gray-200 text-gray-600 hover:text-gray-800 transition-colors z-10';
        closeBtn.innerHTML = '<i class="fas fa-times"></i>';
        closeBtn.onclick = function () {
            if (modal.id) {
                window.safeCloseModal(modal.id);
            } else {
                modal.style.opacity = '0';
                setTimeout(() => modal.remove(), CONFIG.MODAL_ANIMATION_MS);
            }
        };

        // Ensure content has relative positioning
        if (getComputedStyle(content).position === 'static') {
            content.style.position = 'relative';
        }

        content.appendChild(closeBtn);
    }

    // Apply to existing modals
    document.querySelectorAll('.fixed[role="dialog"], .fixed.inset-0').forEach(modal => {
        modal.setAttribute('data-close-on-esc', 'true');
        modal.setAttribute('data-close-on-backdrop', 'true');
        ensureModalCloseButton(modal);
    });

    // ================================================
    // Download limit indicator auto-update
    // ================================================

    setInterval(function () {
        if (typeof updateDownloadLimitIndicator === 'function') {
            updateDownloadLimitIndicator();
        }
    }, 1000);

    console.log('✅ Critical Fixes loaded successfully!');
})();
