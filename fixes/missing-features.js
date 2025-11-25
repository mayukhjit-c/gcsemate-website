/**
 * GCSEMate - Missing Features Implementation
 * Addresses: MF-001 to MF-008
 * Priority: MEDIUM (🟠 to 🟡)
 */

(function () {
    'use strict';

    // Debug logging - silent in production
    const DEBUG = false;
    const log = DEBUG
        ? Function.prototype.bind.call(console.log, console, '➕ [Features]')
        : () => {}; // eslint-disable-line no-console

    log('Loading Missing Features...');

    // ================================================
    // MF-001: PROMINENT DARK MODE TOGGLE
    // ================================================

    /**
     *
     */
    function enhanceThemeToggle() {
        const themeToggle = document.getElementById('theme-toggle');
        if (!themeToggle) {
            return;
        }

        // Make it more visible
        themeToggle.setAttribute('data-tooltip', 'Toggle dark/light mode');
        themeToggle.setAttribute('aria-label', 'Toggle dark or light mode');

        // Update icon based on current theme
        /**
         *
         */
        function updateThemeIcon() {
            const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.className = isDark
                    ? 'fas fa-sun text-yellow-400'
                    : 'fas fa-moon text-blue-600';
            }
        }

        // Watch for theme changes
        const observer = new MutationObserver(updateThemeIcon);
        observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['data-theme'],
        });

        updateThemeIcon();
    }

    // ================================================
    // MF-002: PRINT STYLES
    // ================================================

    const printStyles = document.createElement('style');
    printStyles.id = 'print-styles';
    printStyles.textContent = `
        @media print {
            /* Hide non-essential elements */
            nav,
            header,
            footer,
            #site-watermark,
            #no-ai-badge,
            .mobile-menu,
            #mobile-menu,
            .notification-panel,
            #notification-panel,
            button:not(.print-button),
            .btn:not(.print-button),
            .fixed,
            .sidebar,
            .toast,
            .tooltip,
            [data-tooltip],
            .skeleton,
            .loader,
            .spinner {
                display: none !important;
            }

            /* Reset colors for printing */
            body {
                background: white !important;
                color: black !important;
                font-size: 12pt !important;
                line-height: 1.5 !important;
            }

            /* Make text readable */
            * {
                color: black !important;
                background: transparent !important;
                box-shadow: none !important;
                text-shadow: none !important;
            }

            /* Links */
            a {
                color: black !important;
                text-decoration: underline !important;
            }

            /* Show link URLs */
            a[href]:after {
                content: " (" attr(href) ")";
                font-size: 0.8em;
                color: #666 !important;
            }

            /* Don't show URLs for internal links */
            a[href^="#"]:after,
            a[href^="javascript"]:after {
                content: "";
            }

            /* Cards and containers */
            .card-modern,
            .modern-card,
            .glass-card-premium {
                border: 1px solid #ccc !important;
                break-inside: avoid;
                page-break-inside: avoid;
            }

            /* Images */
            img {
                max-width: 100% !important;
                break-inside: avoid;
            }

            /* Tables */
            table {
                border-collapse: collapse !important;
            }

            th, td {
                border: 1px solid #ccc !important;
                padding: 8px !important;
            }

            /* Page breaks */
            h1, h2, h3 {
                break-after: avoid;
                page-break-after: avoid;
            }

            /* Expand content width */
            .container,
            .max-w-4xl,
            .max-w-6xl,
            .page {
                max-width: 100% !important;
                padding: 0 !important;
                margin: 0 !important;
            }

            /* Show page numbers */
            @page {
                margin: 1cm;
            }

            @page:first {
                margin-top: 2cm;
            }
        }

        /* Print button */
        .print-button {
            display: none;
        }

        @media screen {
            .print-only {
                display: none !important;
            }
        }
    `;

    document.head.appendChild(printStyles);

    // Add print button helper
    window.printPage = function () {
        window.print();
    };

    // ================================================
    // MF-003: OFFLINE INDICATOR
    // ================================================

    /**
     *
     */
    function setupOfflineIndicator() {
        // Create or get offline banner
        let offlineBanner = document.getElementById('offline-status-banner');

        if (!offlineBanner) {
            offlineBanner = document.createElement('div');
            offlineBanner.id = 'offline-status-banner';
            offlineBanner.className =
                'fixed top-0 left-0 right-0 z-[19999] bg-amber-500 text-white py-2 px-4 text-center text-sm font-medium hidden transition-transform duration-300';
            offlineBanner.innerHTML = `
                <i class="fas fa-wifi-slash mr-2"></i>
                You're offline. Some features may be unavailable.
                <button onclick="this.parentElement.classList.add('hidden')" class="ml-4 text-white/80 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            `;
            document.body.insertBefore(offlineBanner, document.body.firstChild);
        }

        /**
         *
         */
        function updateOnlineStatus() {
            if (navigator.onLine) {
                offlineBanner.classList.add('hidden');
                offlineBanner.style.transform = 'translateY(-100%)';
            } else {
                offlineBanner.classList.remove('hidden');
                offlineBanner.style.transform = 'translateY(0)';
            }
        }

        window.addEventListener('online', updateOnlineStatus);
        window.addEventListener('offline', updateOnlineStatus);

        // Initial check
        updateOnlineStatus();
    }

    // ================================================
    // MF-004: BREADCRUMB ON MOBILE
    // ================================================

    const breadcrumbStyles = document.createElement('style');
    breadcrumbStyles.textContent = `
        .breadcrumb,
        nav[aria-label="Breadcrumb"],
        #breadcrumb {
            overflow-x: auto;
            white-space: nowrap;
            -webkit-overflow-scrolling: touch;
            scrollbar-width: none;
            padding: 0.5rem 0;
        }

        .breadcrumb::-webkit-scrollbar {
            display: none;
        }

        /* Fade edges to indicate scroll */
        .breadcrumb-wrapper {
            position: relative;
        }

        .breadcrumb-wrapper::before,
        .breadcrumb-wrapper::after {
            content: '';
            position: absolute;
            top: 0;
            bottom: 0;
            width: 2rem;
            pointer-events: none;
            z-index: 1;
        }

        .breadcrumb-wrapper::before {
            left: 0;
            background: linear-gradient(to right, white, transparent);
        }

        .breadcrumb-wrapper::after {
            right: 0;
            background: linear-gradient(to left, white, transparent);
        }

        [data-theme="dark"] .breadcrumb-wrapper::before {
            background: linear-gradient(to right, #0f172a, transparent);
        }

        [data-theme="dark"] .breadcrumb-wrapper::after {
            background: linear-gradient(to left, #0f172a, transparent);
        }

        /* Compact breadcrumb on mobile */
        @media (max-width: 640px) {
            .breadcrumb-item:not(:last-child):not(:nth-last-child(2)) {
                display: none;
            }

            .breadcrumb-ellipsis {
                display: inline;
            }
        }

        @media (min-width: 641px) {
            .breadcrumb-ellipsis {
                display: none;
            }
        }
    `;
    document.head.appendChild(breadcrumbStyles);

    // ================================================
    // MF-005: SESSION TIMEOUT WARNING
    // ================================================

    let sessionTimeoutId = null;
    let sessionWarningId = null;
    const SESSION_DURATION = 60 * 60 * 1000; // 1 hour
    const WARNING_BEFORE = 5 * 60 * 1000; // 5 minutes before

    /**
     *
     */
    function resetSessionTimeout() {
        clearTimeout(sessionTimeoutId);
        clearTimeout(sessionWarningId);

        // Warning 5 minutes before expiry
        sessionWarningId = setTimeout(() => {
            showSessionWarning();
        }, SESSION_DURATION - WARNING_BEFORE);

        // Actual timeout
        sessionTimeoutId = setTimeout(() => {
            // Session expired - could trigger logout
            if (typeof showToast === 'function') {
                showToast('Your session has expired. Please refresh the page.', 'warning');
            }
        }, SESSION_DURATION);
    }

    /**
     *
     */
    function showSessionWarning() {
        // Check if modal already exists
        if (document.getElementById('session-warning-modal')) {
            return;
        }

        const modal = document.createElement('div');
        modal.id = 'session-warning-modal';
        modal.className =
            'fixed inset-0 z-[20000] flex items-center justify-center bg-black/50 backdrop-blur-sm';
        modal.setAttribute('role', 'alertdialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'session-warning-title');

        modal.innerHTML = `
            <div class="bg-white rounded-2xl shadow-2xl max-w-sm w-full mx-4 p-6">
                <div class="text-center">
                    <div class="w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center mx-auto mb-4">
                        <i class="fas fa-clock text-2xl text-amber-600"></i>
                    </div>
                    <h3 id="session-warning-title" class="text-lg font-bold text-gray-900 mb-2">
                        Session Expiring Soon
                    </h3>
                    <p class="text-gray-600 mb-6">
                        Your session will expire in 5 minutes. Would you like to extend it?
                    </p>
                    <div class="flex gap-3">
                        <button onclick="document.getElementById('session-warning-modal').remove(); resetSessionTimeout();"
                                class="flex-1 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-colors">
                            Extend Session
                        </button>
                        <button onclick="document.getElementById('session-warning-modal').remove();"
                                class="flex-1 py-3 bg-gray-100 text-gray-700 rounded-lg font-semibold hover:bg-gray-200 transition-colors">
                            Dismiss
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    // Reset timeout on user activity
    ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(
            event,
            () => {
                resetSessionTimeout();
            },
            { passive: true, once: false }
        );
    });

    // ================================================
    // MF-006: CALENDAR EXPORT (iCal)
    // ================================================

    window.exportToICal = function (events) {
        if (!events || events.length === 0) {
            if (typeof showToast === 'function') {
                showToast('No events to export', 'warning');
            }
            return;
        }

        const icalContent = [
            'BEGIN:VCALENDAR',
            'VERSION:2.0',
            'PRODID:-//GCSEMate//Calendar//EN',
            'CALSCALE:GREGORIAN',
            'METHOD:PUBLISH',
        ];

        events.forEach(event => {
            const startDate = new Date(event.date);
            const endDate = new Date(startDate);
            endDate.setHours(endDate.getHours() + 1); // 1 hour duration

            icalContent.push(
                'BEGIN:VEVENT',
                `UID:${Date.now()}-${Math.random().toString(36).substr(2, 9)}@gcsemate.com`,
                `DTSTAMP:${formatICalDate(new Date())}`,
                `DTSTART:${formatICalDate(startDate)}`,
                `DTEND:${formatICalDate(endDate)}`,
                `SUMMARY:${escapeICalText(event.title)}`,
                event.description ? `DESCRIPTION:${escapeICalText(event.description)}` : '',
                'END:VEVENT'
            );
        });

        icalContent.push('END:VCALENDAR');

        // Create and download file
        const blob = new Blob([icalContent.filter(Boolean).join('\r\n')], {
            type: 'text/calendar',
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'gcsemate-calendar.ics';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        if (typeof showToast === 'function') {
            showToast('Calendar exported successfully!', 'success');
        }
    };

    /**
     *
     */
    function formatICalDate(date) {
        return date
            .toISOString()
            .replace(/[-:]/g, '')
            .replace(/\.\d{3}/, '');
    }

    /**
     *
     */
    function escapeICalText(text) {
        return text.replace(/[,;\\]/g, '\\$&').replace(/\n/g, '\\n');
    }

    // ================================================
    // MF-007: KEYBOARD NAVIGATION GUIDE (in accessibility-fixes.js)
    // ================================================

    // Keyboard shortcuts are implemented in accessibility-fixes.js
    // Here we add the '/' key for search focus

    document.addEventListener('keydown', function (e) {
        // Don't trigger when typing in inputs
        if (e.target.matches('input, textarea, select, [contenteditable]')) {
            return;
        }

        // '/' to focus search
        if (e.key === '/') {
            e.preventDefault();
            const searchInput = document.querySelector(
                '#file-search-input, #search-input, input[type="search"], input[placeholder*="Search"]'
            );
            if (searchInput) {
                searchInput.focus();
            }
        }

        // 't' to toggle theme
        if (e.key === 't' && !e.ctrlKey && !e.metaKey) {
            const themeToggle = document.getElementById('theme-toggle');
            if (themeToggle) {
                themeToggle.click();
            }
        }
    });

    // ================================================
    // MF-008: PROGRESS INDICATOR FOR LONG OPERATIONS
    // ================================================

    window.showProgress = function (options = {}) {
        const {
            message = 'Loading...',
            type = 'indeterminate', // 'indeterminate' or 'determinate'
            progress = 0,
        } = options;

        let progressEl = document.getElementById('global-progress');

        if (!progressEl) {
            progressEl = document.createElement('div');
            progressEl.id = 'global-progress';
            progressEl.className = 'fixed top-0 left-0 right-0 z-[19998]';
            progressEl.innerHTML = `
                <div class="h-1 bg-gray-200">
                    <div class="progress-fill h-full bg-blue-600 transition-all duration-300" style="width: 0%"></div>
                </div>
                <div class="progress-message hidden bg-blue-600 text-white text-sm py-1 px-4 text-center"></div>
            `;
            document.body.insertBefore(progressEl, document.body.firstChild);
        }

        const fill = progressEl.querySelector('.progress-fill');
        const messageEl = progressEl.querySelector('.progress-message');

        progressEl.style.display = 'block';

        if (type === 'indeterminate') {
            fill.style.width = '30%';
            fill.style.animation = 'progressIndeterminate 1.5s ease-in-out infinite';
        } else {
            fill.style.animation = 'none';
            fill.style.width = `${progress}%`;
        }

        if (message) {
            messageEl.textContent = message;
            messageEl.classList.remove('hidden');
        } else {
            messageEl.classList.add('hidden');
        }

        return {
            update: (newProgress, newMessage) => {
                fill.style.animation = 'none';
                fill.style.width = `${newProgress}%`;
                if (newMessage) {
                    messageEl.textContent = newMessage;
                }
            },
            complete: () => {
                fill.style.width = '100%';
                setTimeout(() => {
                    progressEl.style.display = 'none';
                    fill.style.width = '0%';
                }, 300);
            },
            hide: () => {
                progressEl.style.display = 'none';
                fill.style.width = '0%';
            },
        };
    };

    // Add progress animation
    const progressStyles = document.createElement('style');
    progressStyles.textContent = `
        @keyframes progressIndeterminate {
            0% {
                width: 10%;
                margin-left: 0;
            }
            50% {
                width: 40%;
                margin-left: 30%;
            }
            100% {
                width: 10%;
                margin-left: 90%;
            }
        }
    `;
    document.head.appendChild(progressStyles);

    // ================================================
    // TOAST QUEUE SYSTEM (Enhancement E-003)
    // ================================================

    const toastQueue = [];
    let isShowingToast = false;

    window.queueToast = function (message, type = 'info', duration = 3000) {
        toastQueue.push({ message, type, duration });

        if (!isShowingToast) {
            processToastQueue();
        }
    };

    /**
     *
     */
    function processToastQueue() {
        if (toastQueue.length === 0) {
            isShowingToast = false;
            return;
        }

        isShowingToast = true;
        const { message, type, duration } = toastQueue.shift();

        // Use existing showToast if available, otherwise create simple toast
        if (typeof showToast === 'function') {
            showToast(message, type, duration);
            setTimeout(processToastQueue, duration + 300);
        } else {
            showSimpleToast(message, type, duration);
        }
    }

    /**
     *
     */
    function showSimpleToast(message, type, duration) {
        const colors = {
            success: 'bg-green-600',
            error: 'bg-red-600',
            warning: 'bg-amber-600',
            info: 'bg-blue-600',
        };

        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle',
            info: 'fa-info-circle',
        };

        const toast = document.createElement('div');
        toast.className = `fixed bottom-4 right-4 z-[20001] ${colors[type] || colors.info} text-white px-4 py-3 rounded-lg shadow-lg flex items-center gap-2 toast-enter`;
        toast.innerHTML = `
            <i class="fas ${icons[type] || icons.info}"></i>
            <span>${message}</span>
        `;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.classList.remove('toast-enter');
            toast.classList.add('toast-exit');
            setTimeout(() => {
                toast.remove();
                processToastQueue();
            }, 200);
        }, duration);
    }

    // ================================================
    // INITIALIZATION
    // ================================================

    /**
     *
     */
    function initMissingFeatures() {
        enhanceThemeToggle();
        setupOfflineIndicator();
        resetSessionTimeout();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMissingFeatures);
    } else {
        initMissingFeatures();
    }

    // Make resetSessionTimeout globally available
    window.resetSessionTimeout = resetSessionTimeout;

    log('Missing Features loaded successfully!');
})();
