/**
 * GCSEMate Functional Fixes
 * Implements FI-001 to FI-008 from todo.md
 * @module functional-fixes
 * @version 1.0.0
 */

(function () {
    'use strict';

    // =====================================================================
    // FI-001: Tutorial Modal Persistence
    // Problem: Tutorial shows every time on login
    // Solution: Persist dismissal in localStorage
    // =====================================================================

    /**
     * Manages tutorial modal display state persistence
     */
    const TutorialPersistence = {
        STORAGE_KEY: 'gcsemate_tutorial_dismissed',
        TUTORIAL_VERSION: '1.0', // Increment to force tutorial to show again after updates

        /**
         * Check if tutorial has been dismissed
         * @returns {boolean} True if tutorial was dismissed
         */
        isDismissed() {
            try {
                const data = localStorage.getItem(this.STORAGE_KEY);
                if (!data) {
                    return false;
                }
                const parsed = JSON.parse(data);
                return parsed.version === this.TUTORIAL_VERSION && parsed.dismissed === true;
            } catch {
                return false;
            }
        },

        /**
         * Mark tutorial as dismissed
         */
        dismiss() {
            try {
                localStorage.setItem(
                    this.STORAGE_KEY,
                    JSON.stringify({
                        dismissed: true,
                        version: this.TUTORIAL_VERSION,
                        timestamp: Date.now(),
                    })
                );
            } catch {
                // Storage might be full or blocked
            }
        },

        /**
         * Reset tutorial (for testing or new features)
         */
        reset() {
            try {
                localStorage.removeItem(this.STORAGE_KEY);
            } catch {
                // Ignore errors
            }
        },

        /**
         * Initialize tutorial persistence
         */
        init() {
            // Find tutorial modal
            const tutorialModal =
                document.getElementById('tutorial-modal') ||
                document.querySelector('[data-modal="tutorial"]') ||
                document.querySelector('.tutorial-modal');

            if (!tutorialModal) {
                return;
            }

            // If already dismissed, hide immediately
            if (this.isDismissed()) {
                tutorialModal.classList.add('hidden');
                tutorialModal.setAttribute('aria-hidden', 'true');
                return;
            }

            // Find dismiss buttons
            const dismissButtons = tutorialModal.querySelectorAll(
                '[data-dismiss-tutorial], .tutorial-dismiss, .tutorial-close, [aria-label*="close" i]'
            );

            dismissButtons.forEach(btn => {
                btn.addEventListener('click', () => {
                    this.dismiss();
                });
            });

            // Also handle "Don't show again" checkbox if present
            const dontShowAgain = tutorialModal.querySelector(
                'input[type="checkbox"][name*="dont-show"], input[type="checkbox"][id*="dont-show"]'
            );

            if (dontShowAgain) {
                dontShowAgain.addEventListener('change', e => {
                    if (e.target.checked) {
                        this.dismiss();
                    } else {
                        this.reset();
                    }
                });
            }

            // Intercept the original showTutorial function if it exists
            if (typeof window.showTutorial === 'function') {
                const originalShowTutorial = window.showTutorial;
                window.showTutorial = () => {
                    if (!this.isDismissed()) {
                        originalShowTutorial();
                    }
                };
            }
        },
    };

    // =====================================================================
    // FI-002: Notification Panel Mobile Positioning
    // Problem: Panel positioned incorrectly on mobile
    // Solution: Add responsive positioning CSS
    // =====================================================================

    /**
     * Fixes notification panel positioning on mobile devices
     */
    function fixNotificationPanelPositioning() {
        const style = document.createElement('style');
        style.id = 'notification-panel-mobile-fix';
        style.textContent = `
            /* FI-002: Notification Panel Mobile Positioning Fix */
            #notification-panel,
            .notification-panel,
            [data-notification-panel] {
                position: fixed;
                right: 1rem;
                top: 4rem;
                max-width: 380px;
                max-height: calc(100vh - 5rem);
                overflow-y: auto;
                z-index: 1000;
                border-radius: 0.75rem;
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15);
            }

            /* Mobile positioning */
            @media (max-width: 640px) {
                #notification-panel,
                .notification-panel,
                [data-notification-panel] {
                    position: fixed;
                    left: 0.5rem;
                    right: 0.5rem;
                    top: auto;
                    bottom: 4.5rem;
                    max-width: calc(100vw - 1rem);
                    max-height: 60vh;
                    margin: 0;
                    border-radius: 1rem;
                }
            }

            /* Tablet positioning */
            @media (min-width: 641px) and (max-width: 1024px) {
                #notification-panel,
                .notification-panel,
                [data-notification-panel] {
                    right: 0.75rem;
                    max-width: 340px;
                }
            }

            /* Notification items within panel */
            #notification-panel .notification-item,
            .notification-panel .notification-item {
                padding: 0.75rem;
                border-bottom: 1px solid rgba(0, 0, 0, 0.1);
            }

            .dark #notification-panel .notification-item,
            .dark .notification-panel .notification-item {
                border-bottom-color: rgba(255, 255, 255, 0.1);
            }
        `;
        document.head.appendChild(style);
    }

    // =====================================================================
    // FI-003: File Browser Search Debouncing
    // Problem: Search triggers on every keystroke
    // Solution: Debounce search input
    // =====================================================================

    /**
     * Creates a debounced version of a function
     * @param {Function} func - Function to debounce
     * @param {number} wait - Wait time in ms
     * @returns {Function} Debounced function
     */
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func.apply(this, args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * Applies debouncing to file browser search
     */
    function fixFileBrowserSearch() {
        const searchInput =
            document.getElementById('file-search-input') ||
            document.querySelector('input[type="search"][placeholder*="file" i]') ||
            document.querySelector('.file-search input');

        if (!searchInput) {
            return;
        }

        // Store original handler if exists
        const originalInputHandler = searchInput.oninput;

        // Create debounced handler
        const debouncedSearch = debounce(e => {
            if (originalInputHandler) {
                originalInputHandler.call(searchInput, e);
            }
            // Also dispatch a custom event for any listeners
            searchInput.dispatchEvent(
                new CustomEvent('debouncedSearch', {
                    detail: { query: searchInput.value },
                })
            );
        }, 300);

        // Remove old handler and add debounced one
        searchInput.oninput = null;
        searchInput.addEventListener('input', debouncedSearch);

        // Also patch any existing filterFiles function
        if (typeof window.filterFiles === 'function') {
            const originalFilterFiles = window.filterFiles;
            window.filterFiles = debounce(originalFilterFiles, 300);
        }
    }

    // =====================================================================
    // FI-004: View Toggle Persistence
    // Problem: Grid/List view resets on page refresh
    // Solution: Persist preference in localStorage
    // =====================================================================

    /**
     * Manages view toggle state persistence
     */
    const ViewTogglePersistence = {
        STORAGE_KEY: 'gcsemate_file_browser_view',

        /**
         * Get saved view preference
         * @returns {string} 'grid' or 'list'
         */
        getView() {
            try {
                return localStorage.getItem(this.STORAGE_KEY) || 'list';
            } catch {
                return 'list';
            }
        },

        /**
         * Save view preference
         * @param {string} view - 'grid' or 'list'
         */
        setView(view) {
            try {
                localStorage.setItem(this.STORAGE_KEY, view);
            } catch {
                // Storage might be full or blocked
            }
        },

        /**
         * Initialize view toggle persistence
         */
        init() {
            // Find view toggle buttons
            const gridBtn = document.querySelector(
                '[data-view="grid"], .grid-view-btn, #grid-view-toggle'
            );
            const listBtn = document.querySelector(
                '[data-view="list"], .list-view-btn, #list-view-toggle'
            );
            const fileContainer = document.querySelector(
                '.file-browser, .files-container, #files-container'
            );

            // Apply saved view on load
            const savedView = this.getView();

            if (fileContainer) {
                fileContainer.classList.remove('grid-view', 'list-view');
                fileContainer.classList.add(`${savedView}-view`);
            }

            // Update global state if exists
            if (typeof window.fileBrowserView !== 'undefined') {
                window.fileBrowserView = savedView;
            }

            // Update button states
            if (gridBtn && listBtn) {
                if (savedView === 'grid') {
                    gridBtn.classList.add('active', 'bg-primary-500', 'text-white');
                    listBtn.classList.remove('active', 'bg-primary-500', 'text-white');
                } else {
                    listBtn.classList.add('active', 'bg-primary-500', 'text-white');
                    gridBtn.classList.remove('active', 'bg-primary-500', 'text-white');
                }
            }

            // Add click listeners to persist changes
            if (gridBtn) {
                gridBtn.addEventListener('click', () => {
                    this.setView('grid');
                    if (fileContainer) {
                        fileContainer.classList.remove('list-view');
                        fileContainer.classList.add('grid-view');
                    }
                });
            }

            if (listBtn) {
                listBtn.addEventListener('click', () => {
                    this.setView('list');
                    if (fileContainer) {
                        fileContainer.classList.remove('grid-view');
                        fileContainer.classList.add('list-view');
                    }
                });
            }

            // Patch setFileBrowserView if it exists
            if (typeof window.setFileBrowserView === 'function') {
                const originalSetView = window.setFileBrowserView;
                window.setFileBrowserView = view => {
                    this.setView(view);
                    originalSetView(view);
                };
            }
        },
    };

    // =====================================================================
    // FI-005: Download Rate Limit Real-time Updates
    // Problem: Download limit indicator doesn't update automatically
    // Solution: Add interval to update indicator and countdown
    // =====================================================================

    /**
     * Manages real-time download limit indicator updates
     */
    const DownloadLimitUpdater = {
        updateInterval: null,
        countdownInterval: null,

        /**
         * Update the download limit indicator
         */
        updateIndicator() {
            const indicator =
                document.getElementById('download-limit-indicator') ||
                document.querySelector('.download-limit') ||
                document.querySelector('[data-download-limit]');

            if (!indicator) {
                return;
            }

            // Get current download data from localStorage or global state
            let downloads = [];
            try {
                const stored = localStorage.getItem('gcsemate_downloads');
                if (stored) {
                    downloads = JSON.parse(stored);
                }
            } catch {
                downloads = window.recentDownloads || [];
            }

            // Filter downloads within the last hour
            const oneHourAgo = Date.now() - 60 * 60 * 1000;
            downloads = downloads.filter(d => d.timestamp > oneHourAgo);

            // Update display
            const limit = window.downloadLimit || 5;
            const remaining = Math.max(0, limit - downloads.length);

            // Update indicator text
            const countEl = indicator.querySelector('.download-count') || indicator;
            if (countEl) {
                countEl.textContent = `${remaining}/${limit}`;
            }

            // Update progress bar if present
            const progressBar = indicator.querySelector('.progress-bar, progress');
            if (progressBar) {
                const percentage = (remaining / limit) * 100;
                if (progressBar.tagName === 'PROGRESS') {
                    progressBar.value = remaining;
                    progressBar.max = limit;
                } else {
                    progressBar.style.width = `${percentage}%`;
                }
            }

            // Update color based on remaining
            indicator.classList.remove('text-green-500', 'text-yellow-500', 'text-red-500');
            if (remaining <= 1) {
                indicator.classList.add('text-red-500');
            } else if (remaining <= 2) {
                indicator.classList.add('text-yellow-500');
            } else {
                indicator.classList.add('text-green-500');
            }
        },

        /**
         * Update countdown timer to next reset
         */
        updateCountdown() {
            const countdownEl = document.querySelector('.download-reset-timer, [data-reset-timer]');

            if (!countdownEl) {
                return;
            }

            // Get oldest download timestamp
            let downloads = [];
            try {
                const stored = localStorage.getItem('gcsemate_downloads');
                if (stored) {
                    downloads = JSON.parse(stored);
                }
            } catch {
                downloads = window.recentDownloads || [];
            }

            if (downloads.length === 0) {
                countdownEl.textContent = '';
                return;
            }

            // Find when the oldest download will expire
            const oneHourAgo = Date.now() - 60 * 60 * 1000;
            const oldestValid = downloads
                .filter(d => d.timestamp > oneHourAgo)
                .sort((a, b) => a.timestamp - b.timestamp)[0];

            if (!oldestValid) {
                countdownEl.textContent = '';
                return;
            }

            const resetTime = oldestValid.timestamp + 60 * 60 * 1000;
            const remaining = Math.max(0, resetTime - Date.now());

            const minutes = Math.floor(remaining / 60000);
            const seconds = Math.floor((remaining % 60000) / 1000);

            countdownEl.textContent = `Reset in ${minutes}:${seconds.toString().padStart(2, '0')}`;
        },

        /**
         * Start real-time updates
         */
        start() {
            // Initial update
            this.updateIndicator();
            this.updateCountdown();

            // Update indicator every 5 seconds
            this.updateInterval = setInterval(() => this.updateIndicator(), 5000);

            // Update countdown every second
            this.countdownInterval = setInterval(() => this.updateCountdown(), 1000);
        },

        /**
         * Stop updates
         */
        stop() {
            if (this.updateInterval) {
                clearInterval(this.updateInterval);
            }
            if (this.countdownInterval) {
                clearInterval(this.countdownInterval);
            }
        },
    };

    // Expose for use in other modules
    window.updateDownloadLimitIndicator = () => DownloadLimitUpdater.updateIndicator();

    // =====================================================================
    // FI-006: FAQ Search Highlighting
    // Problem: Search doesn't highlight matching text
    // Solution: Add highlight functionality to FAQ search
    // =====================================================================

    /**
     * Manages FAQ search text highlighting
     */
    const FAQSearchHighlighter = {
        originalContent: new Map(),

        /**
         * Escape special regex characters
         * @param {string} string - String to escape
         * @returns {string} Escaped string safe for regex
         */
        escapeRegex(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        },

        /**
         * Highlight text within an element
         * @param {Element} element - Element to highlight in
         * @param {string} query - Search query
         */
        highlightElement(element, query) {
            if (!query || query.length < 2) {
                this.removeHighlight(element);
                return;
            }

            // Store original content if not already stored
            if (!this.originalContent.has(element)) {
                this.originalContent.set(element, element.innerHTML);
            }

            const original = this.originalContent.get(element);
            const escapedQuery = this.escapeRegex(query);
            const regex = new RegExp(`(${escapedQuery})`, 'gi');

            // Create highlighted version
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = original;

            // Walk text nodes and highlight
            const walker = document.createTreeWalker(tempDiv, NodeFilter.SHOW_TEXT, null, false);

            const nodesToReplace = [];
            let node;
            while ((node = walker.nextNode())) {
                if (regex.test(node.textContent)) {
                    nodesToReplace.push(node);
                }
                regex.lastIndex = 0; // Reset regex
            }

            nodesToReplace.forEach(textNode => {
                const span = document.createElement('span');
                span.innerHTML = textNode.textContent.replace(
                    regex,
                    '<mark class="faq-highlight bg-yellow-300 dark:bg-yellow-600 px-0.5 rounded">$1</mark>'
                );
                textNode.parentNode.replaceChild(span, textNode);
            });

            element.innerHTML = tempDiv.innerHTML;
        },

        /**
         * Remove highlighting from an element
         * @param {Element} element - Element to remove highlighting from
         */
        removeHighlight(element) {
            if (this.originalContent.has(element)) {
                element.innerHTML = this.originalContent.get(element);
            }
        },

        /**
         * Remove all highlights
         */
        removeAllHighlights() {
            this.originalContent.forEach((original, element) => {
                if (element && element.parentNode) {
                    element.innerHTML = original;
                }
            });
            this.originalContent.clear();
        },

        /**
         * Initialize FAQ search highlighting
         */
        init() {
            const searchInput =
                document.getElementById('faq-search') ||
                document.querySelector('input[placeholder*="FAQ" i]') ||
                document.querySelector('.faq-search input');

            if (!searchInput) {
                return;
            }

            const faqContainer = document.querySelector('.faq-container, .faq-list, #faq-section');

            if (!faqContainer) {
                return;
            }

            // Debounced highlight function
            const debouncedHighlight = debounce(query => {
                const faqItems = faqContainer.querySelectorAll(
                    '.faq-item, .faq-question, .faq-answer, details summary, details p'
                );

                faqItems.forEach(item => {
                    this.highlightElement(item, query);
                });
            }, 200);

            searchInput.addEventListener('input', e => {
                const query = e.target.value.trim();
                if (query.length < 2) {
                    this.removeAllHighlights();
                } else {
                    debouncedHighlight(query);
                }
            });

            // Clear highlights when search is cleared
            searchInput.addEventListener('search', () => {
                if (searchInput.value === '') {
                    this.removeAllHighlights();
                }
            });
        },
    };

    // =====================================================================
    // FI-007: Calendar Event Times
    // Problem: Events don't show times
    // Solution: Enhance event display to include times
    // =====================================================================

    /**
     * Fixes calendar event time display
     */
    const CalendarTimeFix = {
        /**
         * Format time for display
         * @param {Date|string|number} date - Date to format
         * @returns {string} Formatted time string
         */
        formatTime(date) {
            const d = new Date(date);
            return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        },

        /**
         * Format date and time for display
         * @param {Date|string|number} date - Date to format
         * @returns {string} Formatted date and time string
         */
        formatDateTime(date) {
            const d = new Date(date);
            return d.toLocaleString([], {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
            });
        },

        /**
         * Enhance event creation modal with time input
         */
        enhanceEventModal() {
            const eventModal =
                document.getElementById('event-modal') ||
                document.getElementById('create-event-modal') ||
                document.querySelector('[data-modal="event"]');

            if (!eventModal) {
                return;
            }

            // Check if time input already exists
            if (eventModal.querySelector('input[type="time"]')) {
                return;
            }

            // Find the date input
            const dateInput = eventModal.querySelector('input[type="date"]');

            if (!dateInput) {
                return;
            }

            // Create time input
            const timeWrapper = document.createElement('div');
            timeWrapper.className = 'mt-3';
            timeWrapper.innerHTML = `
                <label for="event-time" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Time (optional)
                </label>
                <input type="time" id="event-time" name="event-time"
                       class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg
                              bg-white dark:bg-gray-700 text-gray-900 dark:text-white
                              focus:ring-2 focus:ring-primary-500 focus:border-transparent">
            `;

            // Insert after date input
            dateInput.parentNode.insertBefore(timeWrapper, dateInput.nextSibling);
        },

        /**
         * Update event display to show times
         */
        updateEventDisplay() {
            const eventElements = document.querySelectorAll(
                '.calendar-event, .event-item, [data-event-date]'
            );

            eventElements.forEach(event => {
                const dateAttr = event.dataset.eventDate || event.dataset.date;
                const timeAttr = event.dataset.eventTime || event.dataset.time;

                if (!dateAttr) {
                    return;
                }

                // Find or create time display
                let timeDisplay = event.querySelector('.event-time');

                if (!timeDisplay) {
                    timeDisplay = document.createElement('span');
                    timeDisplay.className =
                        'event-time text-sm text-gray-500 dark:text-gray-400 ml-2';

                    const titleEl = event.querySelector('.event-title, .event-name') || event;
                    titleEl.appendChild(timeDisplay);
                }

                if (timeAttr) {
                    timeDisplay.textContent = timeAttr;
                } else {
                    // Try to parse time from date
                    const date = new Date(dateAttr);
                    if (!isNaN(date.getTime()) && date.getHours() !== 0) {
                        timeDisplay.textContent = this.formatTime(date);
                    }
                }
            });
        },

        /**
         * Initialize calendar time fixes
         */
        init() {
            this.enhanceEventModal();

            // Update existing events
            this.updateEventDisplay();

            // Observe for new events being added
            const calendarContainer = document.querySelector(
                '.calendar, #calendar, [data-calendar]'
            );

            if (calendarContainer) {
                const observer = new MutationObserver(() => {
                    this.updateEventDisplay();
                });

                observer.observe(calendarContainer, {
                    childList: true,
                    subtree: true,
                });
            }

            // Patch createEvent if it exists
            if (typeof window.createEvent === 'function') {
                const originalCreateEvent = window.createEvent;
                window.createEvent = function (eventData) {
                    // Include time if available
                    const timeInput = document.getElementById('event-time');
                    if (timeInput && timeInput.value) {
                        eventData.time = timeInput.value;
                    }
                    return originalCreateEvent(eventData);
                };
            }
        },
    };

    // =====================================================================
    // FI-008: Profile Picture Preview
    // Problem: No preview before uploading
    // Solution: Add FileReader preview functionality
    // =====================================================================

    /**
     * Adds profile picture preview functionality
     */
    const ProfilePicturePreview = {
        previewElement: null,

        /**
         * Create preview element
         * @returns {HTMLElement} Preview container element
         */
        createPreviewElement() {
            const preview = document.createElement('div');
            preview.id = 'profile-picture-preview';
            preview.className = `
                hidden mt-3 p-3 border-2 border-dashed border-gray-300 dark:border-gray-600
                rounded-lg text-center
            `.trim();
            preview.innerHTML = `
                <img id="profile-preview-img" src="" alt="Preview"
                     class="w-24 h-24 mx-auto rounded-full object-cover mb-2 hidden">
                <p class="text-sm text-gray-500 dark:text-gray-400" id="preview-filename"></p>
                <button type="button" id="cancel-preview"
                        class="mt-2 text-sm text-red-500 hover:text-red-700 hidden">
                    Cancel
                </button>
            `;
            return preview;
        },

        /**
         * Show preview for selected file
         * @param {File} file - Selected file
         */
        showPreview(file) {
            if (!file || !file.type.startsWith('image/')) {
                this.hidePreview();
                return;
            }

            const reader = new FileReader();

            reader.onload = e => {
                const previewContainer = document.getElementById('profile-picture-preview');
                const previewImg = document.getElementById('profile-preview-img');
                const filename = document.getElementById('preview-filename');
                const cancelBtn = document.getElementById('cancel-preview');

                if (previewContainer && previewImg) {
                    previewImg.src = e.target.result;
                    previewImg.classList.remove('hidden');
                    previewContainer.classList.remove('hidden');

                    if (filename) {
                        filename.textContent = file.name;
                    }

                    if (cancelBtn) {
                        cancelBtn.classList.remove('hidden');
                    }
                }
            };

            reader.onerror = () => {
                this.hidePreview();
            };

            reader.readAsDataURL(file);
        },

        /**
         * Hide preview
         */
        hidePreview() {
            const previewContainer = document.getElementById('profile-picture-preview');
            const previewImg = document.getElementById('profile-preview-img');

            if (previewContainer) {
                previewContainer.classList.add('hidden');
            }

            if (previewImg) {
                previewImg.src = '';
                previewImg.classList.add('hidden');
            }
        },

        /**
         * Initialize profile picture preview
         */
        init() {
            // Find profile picture input
            const fileInput =
                document.getElementById('profile-picture-input') ||
                document.querySelector('input[type="file"][accept*="image"]') ||
                document.querySelector('.profile-picture input[type="file"]');

            if (!fileInput) {
                return;
            }

            // Create and insert preview element
            const preview = this.createPreviewElement();
            fileInput.parentNode.insertBefore(preview, fileInput.nextSibling);

            // Add change listener
            fileInput.addEventListener('change', e => {
                const file = e.target.files[0];
                if (file) {
                    this.showPreview(file);
                } else {
                    this.hidePreview();
                }
            });

            // Cancel button handler
            const cancelBtn = document.getElementById('cancel-preview');
            if (cancelBtn) {
                cancelBtn.addEventListener('click', () => {
                    fileInput.value = '';
                    this.hidePreview();
                });
            }
        },
    };

    // =====================================================================
    // Add CSS for functional fixes
    // =====================================================================

    /**
     *
     */
    function addFunctionalFixesStyles() {
        const style = document.createElement('style');
        style.id = 'functional-fixes-styles';
        style.textContent = `
            /* FI-006: FAQ Highlight styles */
            .faq-highlight {
                background-color: #fef08a;
                padding: 0 2px;
                border-radius: 2px;
            }

            .dark .faq-highlight {
                background-color: #ca8a04;
                color: #fff;
            }

            /* FI-008: Profile preview styles */
            #profile-picture-preview {
                transition: all 0.3s ease;
            }

            #profile-picture-preview.hidden {
                display: none;
            }

            #profile-preview-img {
                border: 3px solid var(--primary-500, #6366f1);
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }

            /* FI-005: Download limit indicator styles */
            .download-limit {
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }

            .download-reset-timer {
                font-size: 0.75rem;
                color: #6b7280;
            }

            .dark .download-reset-timer {
                color: #9ca3af;
            }

            /* FI-004: View toggle active states */
            .view-toggle-btn.active {
                background-color: var(--primary-500, #6366f1);
                color: white;
            }

            /* HIDE orphaned notes-content section */
            body > #notes-content,
            #page-content > #notes-content,
            #page-container > #notes-content,
            #notes-content:not(.inside-tools-page) {
                display: none !important;
            }

            /* FIX: Double scrollbar - only one scrollbar on body */
            html {
                overflow-y: auto;
                overflow-x: hidden;
            }
            body {
                overflow: hidden;
                height: 100vh;
            }
            #page-content,
            main,
            .main-content {
                overflow-y: auto;
                overflow-x: hidden;
                height: calc(100vh - 64px);
            }
            .page {
                overflow: visible;
            }
            /* Prevent nested scrollbars */
            .page .overflow-y-auto,
            .page .overflow-auto {
                max-height: none;
            }

            /* FIX: AI Tutor page spacing - AGGRESSIVELY remove blank space above */
            #ai-tutor-page {
                padding-top: 0 !important;
                margin-top: 0 !important;
                position: relative !important;
                top: 0 !important;
            }
            #ai-tutor-page.page {
                padding-top: 0.5rem !important;
            }
            #ai-tutor-page > *:first-child {
                margin-top: 0 !important;
                padding-top: 0 !important;
            }
            #ai-tutor-page .flex:first-child,
            #ai-tutor-page > .flex.flex-col:first-child,
            #ai-tutor-page > div:first-child {
                margin-top: 0 !important;
                padding-top: 0 !important;
            }
            /* Remove any spacing that might be above AI tutor page container */
            #page-container > #ai-tutor-page {
                margin-top: 0 !important;
            }
            /* Ensure no gap between nav and content */
            #page-content {
                padding-top: 0 !important;
            }
            #page-container {
                padding-top: 0 !important;
                margin-top: 0 !important;
            }

            /* ═══════════════════════════════════════════════════════════════ */
            /* ENHANCED MODERN ANIMATIONS & POLISH */
            /* ═══════════════════════════════════════════════════════════════ */

            /* Smooth page transitions */
            .page {
                animation: pageEnter 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            }
            @keyframes pageEnter {
                from {
                    opacity: 0;
                    transform: translateY(8px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            /* Modern card hover effects */
            .bg-white\\/70,
            .bg-white,
            [class*="rounded-xl"],
            [class*="rounded-2xl"] {
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }

            .bg-white\\/70:hover,
            .shadow-lg:hover {
                transform: translateY(-2px);
                box-shadow: 0 20px 40px -12px rgba(0, 0, 0, 0.15);
            }

            /* Smooth button interactions */
            button, .btn, [role="button"] {
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            }

            button:active:not(:disabled),
            .btn:active:not(:disabled) {
                transform: scale(0.98);
            }

            /* Modern focus states */
            button:focus-visible,
            a:focus-visible,
            input:focus-visible,
            textarea:focus-visible,
            select:focus-visible {
                outline: 2px solid #0ea5e9;
                outline-offset: 2px;
                border-radius: 4px;
            }

            /* Smooth input transitions */
            input, textarea, select {
                transition: border-color 0.2s, box-shadow 0.2s, background-color 0.2s;
            }

            input:focus, textarea:focus, select:focus {
                border-color: #0ea5e9 !important;
                box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.15) !important;
            }

            /* Modern loading spinner */
            @keyframes modernSpin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            .animate-spin, [class*="fa-spinner"], [class*="fa-circle-notch"] {
                animation: modernSpin 0.8s linear infinite;
            }

            /* Smooth icon animations */
            i[class*="fa-"], svg {
                transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1), color 0.2s;
            }

            button:hover i[class*="fa-"],
            a:hover i[class*="fa-"] {
                transform: scale(1.1);
            }

            /* Modal entrance animation */
            .fixed.inset-0[class*="z-"] > div {
                animation: modalEnter 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
            }
            @keyframes modalEnter {
                from {
                    opacity: 0;
                    transform: scale(0.95) translateY(-10px);
                }
                to {
                    opacity: 1;
                    transform: scale(1) translateY(0);
                }
            }

            /* Smooth dropdown animations */
            .dropdown-menu, [id*="-panel"]:not(.hidden), [id*="-dropdown"]:not(.hidden) {
                animation: dropdownEnter 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            }
            @keyframes dropdownEnter {
                from {
                    opacity: 0;
                    transform: translateY(-8px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            /* Toast notification animation */
            .toast, [class*="toast"], #toast-container > * {
                animation: toastSlide 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
            }
            @keyframes toastSlide {
                from {
                    opacity: 0;
                    transform: translateX(100%) scale(0.9);
                }
                to {
                    opacity: 1;
                    transform: translateX(0) scale(1);
                }
            }

            /* Polished scrollbar */
            ::-webkit-scrollbar {
                width: 10px;
                height: 10px;
            }
            ::-webkit-scrollbar-track {
                background: rgba(0, 0, 0, 0.05);
                border-radius: 10px;
            }
            ::-webkit-scrollbar-thumb {
                background: linear-gradient(180deg, #0ea5e9, #0284c7);
                border-radius: 10px;
                border: 2px solid transparent;
                background-clip: padding-box;
            }
            ::-webkit-scrollbar-thumb:hover {
                background: linear-gradient(180deg, #0284c7, #0369a1);
                background-clip: padding-box;
            }

            /* Smooth skeleton loading */
            @keyframes skeletonPulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .skeleton, .animate-pulse {
                animation: skeletonPulse 1.5s ease-in-out infinite;
            }

            /* Professional shadow on hover for cards */
            .hover\\:shadow-xl:hover,
            .hover\\:shadow-lg:hover {
                box-shadow:
                    0 25px 50px -12px rgba(0, 0, 0, 0.15),
                    0 0 0 1px rgba(0, 0, 0, 0.05);
            }

            /* Glassmorphism polish */
            .backdrop-blur-lg {
                backdrop-filter: blur(20px) saturate(180%);
                -webkit-backdrop-filter: blur(20px) saturate(180%);
            }

            /* Better text selection */
            ::selection {
                background: rgba(14, 165, 233, 0.3);
                color: inherit;
            }

            /* Smooth nav link transitions */
            .nav-link {
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            }
            .nav-link:hover {
                transform: translateX(2px);
            }
            .nav-link.active {
                background: linear-gradient(135deg, rgba(14, 165, 233, 0.1), rgba(14, 165, 233, 0.05));
                border-left: 3px solid #0ea5e9;
            }

            /* FIX: Study timer stop button - ensure proper visibility */
            #study-stop-btn {
                display: none !important;
            }
            #study-stop-btn.visible,
            #study-stop-btn:not(.hidden),
            body.study-session-active #study-stop-btn {
                display: inline-flex !important;
            }
            #study-start-btn.hidden,
            body.study-session-active #study-start-btn {
                display: none !important;
            }
        `;
        document.head.appendChild(style);
    }

    // =====================================================================
    // FIX: Study Session Timer - Ensure it starts properly
    // =====================================================================

    /**
     * Enhanced Study Session Timer Fix
     */
    const StudySessionFix = {
        init() {
            // Wait for DOM to be ready
            const startBtn = document.getElementById('study-start-btn');
            const stopBtn = document.getElementById('study-stop-btn');
            const timerDisplay = document.getElementById('study-timer-display');

            if (!startBtn) {
                return;
            }

            // Ensure the timer display exists
            if (!timerDisplay) {
                // Create timer display if missing
                const sessionContainer =
                    startBtn.closest('.bg-white\\/70') || startBtn.parentElement;
                if (sessionContainer) {
                    const existingTimer = sessionContainer.querySelector('#study-timer-display');
                    if (!existingTimer) {
                        const timerEl = document.createElement('div');
                        timerEl.id = 'study-timer-display';
                        timerEl.className =
                            'text-3xl font-mono font-bold text-gray-900 dark:text-white text-center my-4';
                        timerEl.textContent = '00:00:00';
                        const buttonsDiv =
                            sessionContainer.querySelector('.flex.gap-3') || startBtn.parentElement;
                        if (buttonsDiv) {
                            buttonsDiv.parentElement.insertBefore(timerEl, buttonsDiv);
                        }
                    }
                }
            }

            // Add click handler to ensure StudyProgress is properly called
            startBtn.addEventListener(
                'click',
                () => {
                    // Ensure StudyProgress exists
                    if (typeof window.StudyProgress === 'undefined') {
                        console.warn('StudyProgress not initialized');
                        return;
                    }

                    const subjectInput = document.getElementById('study-subject-input');
                    const subject = subjectInput?.value?.trim() || 'General Study';

                    // Clear any existing timer
                    if (window.StudyProgress.sessionTimer) {
                        clearInterval(window.StudyProgress.sessionTimer);
                    }

                    // Start the session
                    window.StudyProgress.sessionStartTime = Date.now();
                    window.StudyProgress.currentSubject = subject;

                    // Create the timer interval
                    window.StudyProgress.sessionTimer = setInterval(() => {
                        const elapsed = Math.floor(
                            (Date.now() - window.StudyProgress.sessionStartTime) / 1000
                        );
                        const hours = Math.floor(elapsed / 3600);
                        const minutes = Math.floor((elapsed % 3600) / 60);
                        const seconds = elapsed % 60;

                        const display = document.getElementById('study-timer-display');
                        if (display) {
                            display.textContent = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                        }
                    }, 1000);

                    // Update UI - Use inline styles for reliable toggling
                    startBtn.style.display = 'none';
                    if (stopBtn) {
                        stopBtn.style.display = 'inline-flex';
                    }
                    document.body.classList.add('study-session-active');

                    // Show initial time
                    const display = document.getElementById('study-timer-display');
                    if (display) {
                        display.textContent = '00:00:00';
                    }

                    if (typeof showToast === 'function') {
                        showToast(`Tracking study session for ${subject}`, 'success');
                    }
                },
                { capture: true }
            );

            // Handle stop button
            if (stopBtn) {
                stopBtn.addEventListener(
                    'click',
                    () => {
                        if (window.StudyProgress?.sessionTimer) {
                            clearInterval(window.StudyProgress.sessionTimer);
                            window.StudyProgress.sessionTimer = null;
                        }

                        // Calculate duration
                        if (window.StudyProgress?.sessionStartTime) {
                            const durationMs = Date.now() - window.StudyProgress.sessionStartTime;
                            const minutes = Math.floor(durationMs / 60000);

                            if (typeof showToast === 'function') {
                                showToast(`Study session saved (${minutes} minutes)`, 'success');
                            }

                            window.StudyProgress.sessionStartTime = null;
                            window.StudyProgress.currentSubject = null;
                        }

                        // Update UI - Use inline styles for reliable toggling
                        if (startBtn) {
                            startBtn.style.display = 'inline-flex';
                        }
                        stopBtn.style.display = 'none';
                        document.body.classList.remove('study-session-active');
                    },
                    { capture: true }
                );
            }
        },
    };

    // =====================================================================
    // Initialize all functional fixes
    // =====================================================================

    /**
     *
     */
    function initFunctionalFixes() {
        // Add styles first
        addFunctionalFixesStyles();

        // Initialize all fixes
        TutorialPersistence.init();
        fixNotificationPanelPositioning();
        fixFileBrowserSearch();
        ViewTogglePersistence.init();
        DownloadLimitUpdater.start();
        FAQSearchHighlighter.init();
        CalendarTimeFix.init();
        ProfilePicturePreview.init();
        StudySessionFix.init();

        // Expose utilities globally for other modules
        window.GCSEMateFunctionalFixes = {
            TutorialPersistence,
            ViewTogglePersistence,
            DownloadLimitUpdater,
            FAQSearchHighlighter,
            CalendarTimeFix,
            ProfilePicturePreview,
            StudySessionFix,
            debounce,
        };
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initFunctionalFixes);
    } else {
        initFunctionalFixes();
    }
})();
