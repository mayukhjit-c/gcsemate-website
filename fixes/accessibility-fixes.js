/**
 * GCSEMate - Accessibility Fixes
 * Addresses: A-001 to A-008
 * Priority: HIGH (🔴 to 🟠)
 */

(function () {
    'use strict';

    // Debug logging - silent in production
    const DEBUG = false;
    const log = DEBUG
        ? Function.prototype.bind.call(console.log, console, '♿ [Accessibility]') // eslint-disable-line no-console
        : () => {};

    log('Loading Accessibility Fixes...');

    // ================================================
    // A-001: ADD ARIA LABELS TO INTERACTIVE ELEMENTS
    // ================================================

    const ariaLabelMappings = {
        // Icon-only buttons
        '.fa-moon': 'Toggle dark mode',
        '.fa-sun': 'Toggle light mode',
        '.fa-bell': 'Notifications',
        '.fa-times': 'Close',
        '.fa-close': 'Close',
        '.fa-search': 'Search',
        '.fa-bars': 'Open menu',
        '.fa-user': 'User profile',
        '.fa-cog': 'Settings',
        '.fa-gear': 'Settings',
        '.fa-home': 'Home',
        '.fa-sign-out': 'Sign out',
        '.fa-sign-out-alt': 'Sign out',
        '.fa-download': 'Download',
        '.fa-upload': 'Upload',
        '.fa-edit': 'Edit',
        '.fa-pencil': 'Edit',
        '.fa-trash': 'Delete',
        '.fa-trash-alt': 'Delete',
        '.fa-plus': 'Add',
        '.fa-minus': 'Remove',
        '.fa-chevron-left': 'Previous',
        '.fa-chevron-right': 'Next',
        '.fa-chevron-up': 'Expand',
        '.fa-chevron-down': 'Collapse',
        '.fa-arrow-left': 'Go back',
        '.fa-arrow-right': 'Go forward',
        '.fa-refresh': 'Refresh',
        '.fa-sync': 'Refresh',
        '.fa-star': 'Favorite',
        '.fa-heart': 'Like',
        '.fa-share': 'Share',
        '.fa-copy': 'Copy',
        '.fa-clipboard': 'Copy to clipboard',
        '.fa-external-link': 'Open in new tab',
        '.fa-external-link-alt': 'Open in new tab',
        '.fa-eye': 'View',
        '.fa-eye-slash': 'Hide',
        '.fa-play': 'Play',
        '.fa-pause': 'Pause',
        '.fa-stop': 'Stop',
        '.fa-volume-up': 'Volume',
        '.fa-volume-mute': 'Mute',
        '.fa-expand': 'Fullscreen',
        '.fa-compress': 'Exit fullscreen',
        '.fa-filter': 'Filter',
        '.fa-sort': 'Sort',
        '.fa-calendar': 'Calendar',
        '.fa-calendar-alt': 'Calendar',
        '.fa-clock': 'Time',
        '.fa-info': 'Information',
        '.fa-info-circle': 'Information',
        '.fa-question': 'Help',
        '.fa-question-circle': 'Help',
        '.fa-exclamation': 'Warning',
        '.fa-exclamation-circle': 'Warning',
        '.fa-check': 'Confirm',
        '.fa-check-circle': 'Confirmed',
    };

    /**
     *
     */
    function addAriaLabels() {
        // Find icon-only buttons
        document.querySelectorAll('button, a').forEach(element => {
            // Skip if already has accessible label
            if (
                element.getAttribute('aria-label') ||
                element.getAttribute('aria-labelledby') ||
                element.textContent.trim().length > 0
            ) {
                return;
            }

            // Find icon inside
            const icon = element.querySelector('[class*="fa-"]');
            if (!icon) {
                return;
            }

            // Try to find matching label
            for (const [selector, label] of Object.entries(ariaLabelMappings)) {
                if (icon.matches(selector) || icon.classList.contains(selector.replace('.', ''))) {
                    element.setAttribute('aria-label', label);
                    break;
                }
            }

            // Fallback: extract from icon class name
            if (!element.getAttribute('aria-label')) {
                const iconClass = Array.from(icon.classList).find(c => c.startsWith('fa-'));
                if (iconClass) {
                    const label = iconClass.replace('fa-', '').replace(/-/g, ' ');
                    element.setAttribute(
                        'aria-label',
                        label.charAt(0).toUpperCase() + label.slice(1)
                    );
                }
            }
        });
    }

    // ================================================
    // A-003: COLOR CONTRAST FIXES
    // ================================================

    /**
     *
     */
    function fixColorContrast() {
        // Create style element for contrast fixes
        const style = document.createElement('style');
        style.id = 'accessibility-contrast-fixes';
        style.textContent = `
            /* Fix gray text contrast - WCAG 2.1 AA compliant */
            .text-gray-400 { color: #6b7280 !important; }
            .text-gray-500 { color: #4b5563 !important; }
            .text-gray-600 { color: #374151 !important; }

            /* Improved placeholder contrast */
            ::placeholder {
                color: #6b7280 !important;
                opacity: 1 !important;
            }
            ::-webkit-input-placeholder { color: #6b7280 !important; }
            ::-moz-placeholder { color: #6b7280 !important; }
            :-ms-input-placeholder { color: #6b7280 !important; }

            /* Ensure sufficient contrast on light backgrounds */
            .bg-white .text-gray-400,
            .bg-gray-50 .text-gray-400,
            .bg-gray-100 .text-gray-400 {
                color: #4b5563 !important;
            }

            /* Dark mode contrast fixes */
            [data-theme="dark"] .text-gray-400 { color: #9ca3af !important; }
            [data-theme="dark"] .text-gray-500 { color: #d1d5db !important; }
            [data-theme="dark"] ::placeholder { color: #9ca3af !important; }

            /* Link contrast */
            a:not([class*="text-"]) {
                color: #2563eb;
            }
            a:not([class*="text-"]):hover {
                color: #1d4ed8;
            }

            /* Button contrast on hover */
            button:focus-visible,
            a:focus-visible {
                outline: 3px solid rgba(59, 130, 246, 0.5) !important;
                outline-offset: 2px !important;
            }

            /* Error message contrast */
            .text-red-500 { color: #dc2626 !important; }
            .text-red-600 { color: #dc2626 !important; }

            /* Success message contrast */
            .text-green-500 { color: #059669 !important; }
            .text-green-600 { color: #059669 !important; }
        `;

        // Remove existing if present
        const existing = document.getElementById('accessibility-contrast-fixes');
        if (existing) {
            existing.remove();
        }

        document.head.appendChild(style);
    }

    // ================================================
    // A-004: FIX SKIP LINK VISIBILITY
    // ================================================

    /**
     *
     */
    function fixSkipLink() {
        const style = document.createElement('style');
        style.id = 'skip-link-fixes';
        style.textContent = `
            /* Enhanced skip link visibility on focus */
            a[href="#page-content"].sr-only:focus,
            a[href="#main-content"].sr-only:focus,
            .skip-link:focus {
                position: fixed !important;
                top: 0.5rem !important;
                left: 0.5rem !important;
                z-index: 99999 !important;
                width: auto !important;
                height: auto !important;
                padding: 0.75rem 1.5rem !important;
                clip: auto !important;
                overflow: visible !important;
                white-space: nowrap !important;
                background: #2563eb !important;
                color: white !important;
                border-radius: 0.5rem !important;
                font-weight: 600 !important;
                text-decoration: none !important;
                box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4) !important;
            }
        `;

        const existing = document.getElementById('skip-link-fixes');
        if (existing) {
            existing.remove();
        }

        document.head.appendChild(style);

        // Ensure skip link exists
        let skipLink = document.querySelector('a[href="#page-content"], a[href="#main-content"]');
        if (!skipLink) {
            skipLink = document.createElement('a');
            skipLink.href = '#page-content';
            skipLink.className = 'sr-only skip-link';
            skipLink.textContent = 'Skip to main content';
            document.body.insertBefore(skipLink, document.body.firstChild);
        }

        // Ensure target exists
        const mainContent =
            document.getElementById('page-content') || document.getElementById('landing-content') || document.querySelector('main');
        if (mainContent && !mainContent.id) {
            mainContent.id = 'page-content';
        }
    }

    // ================================================
    // A-005: FORM ERROR MESSAGE ANNOUNCEMENTS
    // ================================================

    /**
     *
     */
    function setupErrorAnnouncements() {
        // Find all error message containers
        document
            .querySelectorAll('[id*="error"], .error-message, .text-red-500, .text-red-600')
            .forEach(el => {
                if (!el.getAttribute('role')) {
                    el.setAttribute('role', 'alert');
                }
                if (!el.getAttribute('aria-live')) {
                    el.setAttribute('aria-live', 'assertive');
                }
                if (!el.getAttribute('aria-atomic')) {
                    el.setAttribute('aria-atomic', 'true');
                }
            });

        // Link error messages to their inputs
        document.querySelectorAll('input, textarea, select').forEach(input => {
            const errorId = input.id + '-error';
            const errorEl = document.getElementById(errorId);

            if (errorEl && !input.getAttribute('aria-describedby')) {
                input.setAttribute('aria-describedby', errorId);
            }
        });
    }

    // ================================================
    // A-006: ADD ALT TEXT TO IMAGES
    // ================================================

    /**
     *
     */
    function fixImageAltText() {
        document.querySelectorAll('img').forEach(img => {
            // Skip if already has alt
            if (img.hasAttribute('alt') && img.alt !== '') {
                return;
            }

            // Check if decorative (aria-hidden or in decorative container)
            if (img.getAttribute('aria-hidden') === 'true' || img.closest('[aria-hidden="true"]')) {
                img.alt = '';
                return;
            }

            // Try to derive alt text
            let altText = '';

            // Check title attribute
            if (img.title) {
                altText = img.title;
            }
            // Check parent link or button
            else if (img.closest('a, button')) {
                const parent = img.closest('a, button');
                altText = parent.getAttribute('aria-label') || parent.textContent.trim();
            }
            // Check filename
            else if (img.src) {
                const filename = img.src.split('/').pop().split('?')[0];
                const name = filename.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' ');
                altText = name.charAt(0).toUpperCase() + name.slice(1);
            }

            // Set alt text or mark as decorative
            if (altText) {
                img.alt = altText;
            } else {
                img.alt = '';
                img.setAttribute('aria-hidden', 'true');
            }
        });
    }

    // ================================================
    // A-007: FIX HEADING HIERARCHY
    // ================================================

    /**
     *
     */
    function checkHeadingHierarchy() {
        const headings = document.querySelectorAll('h1, h2, h3, h4, h5, h6');
        const issues = [];
        let lastLevel = 0;

        headings.forEach((heading, index) => {
            const level = parseInt(heading.tagName[1]);

            // Check for skipped levels
            if (lastLevel > 0 && level > lastLevel + 1) {
                issues.push({
                    element: heading,
                    issue: `Heading level skipped from h${lastLevel} to h${level}`,
                    index: index,
                });
            }

            lastLevel = level;
        });

        // Log issues for developers
        if (issues.length > 0 && console.warn) {
            console.warn('Heading hierarchy issues found:', issues);
        }

        return issues;
    }

    // ================================================
    // A-008: KEYBOARD SHORTCUTS HELP
    // ================================================

    const keyboardShortcuts = {
        '?': 'Show keyboard shortcuts',
        Escape: 'Close modal/dialog',
        '/': 'Focus search',
        'g h': 'Go to home',
        'g s': 'Go to subjects',
        'g c': 'Go to calendar',
        'g b': 'Go to blog',
        t: 'Toggle theme',
    };

    /**
     *
     */
    function createKeyboardShortcutsModal() {
        // Check if already exists
        if (document.getElementById('keyboard-shortcuts-modal')) {
            return;
        }

        const modal = document.createElement('div');
        modal.id = 'keyboard-shortcuts-modal';
        modal.className =
            'fixed inset-0 z-[20000] hidden items-center justify-center bg-black/50 backdrop-blur-sm';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'keyboard-shortcuts-title');
        modal.setAttribute('data-close-on-esc', 'true');
        modal.setAttribute('data-close-on-backdrop', 'true');

        modal.innerHTML = `
            <div class="modal-content bg-white rounded-2xl shadow-2xl max-w-lg w-full mx-4 max-h-[80vh] overflow-y-auto">
                <div class="p-6 border-b border-gray-200">
                    <div class="flex items-center justify-between">
                        <h2 id="keyboard-shortcuts-title" class="text-xl font-bold text-gray-900">
                            <i class="fas fa-keyboard mr-2 text-blue-600"></i>
                            Keyboard Shortcuts
                        </h2>
                        <button onclick="safeCloseModal('keyboard-shortcuts-modal')"
                                class="w-8 h-8 flex items-center justify-center rounded-full bg-gray-100 hover:bg-gray-200 text-gray-600"
                                aria-label="Close">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>
                <div class="p-6">
                    <dl class="space-y-3">
                        ${Object.entries(keyboardShortcuts)
                            .map(
                                ([key, action]) => `
                            <div class="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
                                <dt class="text-gray-600">${action}</dt>
                                <dd>
                                    <kbd class="px-2 py-1 bg-gray-100 rounded text-sm font-mono text-gray-800 shadow-sm">
                                        ${key}
                                    </kbd>
                                </dd>
                            </div>
                        `
                            )
                            .join('')}
                    </dl>
                </div>
                <div class="p-4 bg-gray-50 rounded-b-2xl text-center text-sm text-gray-500">
                    Press <kbd class="px-1 bg-gray-200 rounded">?</kbd> anytime to show this help
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    // Show keyboard shortcuts on '?' key
    document.addEventListener('keydown', function (e) {
        // Don't trigger when typing in inputs
        if (e.target.matches('input, textarea, select, [contenteditable]')) {
            return;
        }

        if (e.key === '?' || (e.shiftKey && e.key === '/')) {
            e.preventDefault();
            createKeyboardShortcutsModal();
            const modal = document.getElementById('keyboard-shortcuts-modal');
            if (modal) {
                modal.classList.remove('hidden');
                modal.style.display = 'flex';
            }
        }
    });

    // Add hint to footer about keyboard shortcuts
    /**
     *
     */
    function addKeyboardHint() {
        const footer = document.querySelector('footer');
        if (!footer) {
            return;
        }

        // Check if hint already exists
        if (footer.querySelector('.keyboard-hint')) {
            return;
        }

        const hint = document.createElement('p');
        hint.className = 'keyboard-hint text-xs text-gray-400 mt-2 text-center';
        hint.innerHTML =
            'Press <kbd class="px-1 bg-gray-200 rounded text-gray-600">?</kbd> for keyboard shortcuts';

        const container = footer.querySelector('.text-center') || footer;
        container.appendChild(hint);
    }

    // ================================================
    // LIVE REGION FOR DYNAMIC CONTENT UPDATES
    // ================================================

    /**
     *
     */
    function createLiveRegion() {
        if (document.getElementById('a11y-live-region')) {
            return;
        }

        const liveRegion = document.createElement('div');
        liveRegion.id = 'a11y-live-region';
        liveRegion.className = 'sr-only';
        liveRegion.setAttribute('aria-live', 'polite');
        liveRegion.setAttribute('aria-atomic', 'true');
        document.body.appendChild(liveRegion);
    }

    window.announceToScreenReader = function (message, priority = 'polite') {
        const liveRegion = document.getElementById('a11y-live-region');
        if (!liveRegion) {
            return;
        }

        liveRegion.setAttribute('aria-live', priority);
        liveRegion.textContent = '';

        // Small delay to ensure the change is announced
        setTimeout(() => {
            liveRegion.textContent = message;
        }, 100);
    };

    // ================================================
    // APPLY ALL ACCESSIBILITY FIXES
    // ================================================

    /**
     *
     */
    function applyAllAccessibilityFixes() {
        addAriaLabels();
        fixColorContrast();
        fixSkipLink();
        setupErrorAnnouncements();
        fixImageAltText();
        checkHeadingHierarchy();
        createLiveRegion();
        addKeyboardHint();
        createKeyboardShortcutsModal();
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyAllAccessibilityFixes);
    } else {
        applyAllAccessibilityFixes();
    }

    // Re-apply on dynamic content
    const accessibilityObserver = new MutationObserver(function (mutations) {
        let shouldReapply = false;

        mutations.forEach(mutation => {
            if (mutation.addedNodes.length > 0) {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) {
                        // Element node
                        shouldReapply = true;
                    }
                });
            }
        });

        if (shouldReapply) {
            // Debounce to avoid too frequent updates
            clearTimeout(accessibilityObserver._timeout);
            accessibilityObserver._timeout = setTimeout(() => {
                addAriaLabels();
                setupErrorAnnouncements();
                fixImageAltText();
            }, 500);
        }
    });

    accessibilityObserver.observe(document.body, { childList: true, subtree: true });

    log('Accessibility Fixes loaded successfully!');
})();
