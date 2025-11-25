/**
 * GCSEMate - Enhancement Features Implementation
 * Addresses: E-001 to E-015 from todo.md
 * Priority: LOW (🟢)
 */

(function () {
    'use strict';

    // Debug logging - silent in production
    const DEBUG = false;
    const log = DEBUG
        ? Function.prototype.bind.call(console.log, console, '✨ [Enhancements]') // eslint-disable-line no-console
        : () => {};

    log('Loading Enhancement Features...');

    // Store references for initialization
    let pageProgress = null;
    let progressFill = null;

    // ================================================
    // E-001: PAGE LOAD PROGRESS BAR
    // ================================================

    /**
     * Initialize page progress bar
     */
    function initPageProgress() {
        // Only initialize if not already done
        if (document.getElementById('page-progress-styles')) {
            return;
        }

        const pageProgressStyles = document.createElement('style');
        pageProgressStyles.id = 'page-progress-styles';
        pageProgressStyles.textContent = `
            #page-progress {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                z-index: 99999;
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.2s ease;
            }

            #page-progress.active {
                opacity: 1;
            }

            #page-progress .progress-fill {
                height: 100%;
                width: 0%;
                background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
                background-size: 200% 100%;
                animation: shimmer 2s linear infinite;
                transition: width 0.3s ease;
                border-radius: 0 2px 2px 0;
            }

            @keyframes shimmer {
                0% { background-position: -200% 0; }
                100% { background-position: 200% 0; }
            }
        `;
        document.head.appendChild(pageProgressStyles);

        // Create progress bar element
        pageProgress = document.createElement('div');
        pageProgress.id = 'page-progress';
        pageProgress.innerHTML = '<div class="progress-fill"></div>';

        // Append to body instead of inserting before firstChild
        if (document.body) {
            document.body.appendChild(pageProgress);
            progressFill = pageProgress.querySelector('.progress-fill');
        }
    }

    window.startPageProgress = function () {
        if (!progressFill) {
            return;
        }
        progressFill.style.width = '0%';
        pageProgress.classList.add('active');
        // Animate to 70% over time
        setTimeout(() => {
            progressFill.style.width = '30%';
        }, 50);
        setTimeout(() => {
            progressFill.style.width = '50%';
        }, 200);
        setTimeout(() => {
            progressFill.style.width = '70%';
        }, 500);
    };

    window.completePageProgress = function () {
        progressFill.style.width = '100%';
        setTimeout(() => {
            pageProgress.classList.remove('active');
            progressFill.style.width = '0%';
        }, 300);
    };

    // Auto-trigger on page navigation (for SPA)
    const originalShowPage = window.showPage;
    if (typeof originalShowPage === 'function') {
        window.showPage = function (...args) {
            window.startPageProgress();
            const result = originalShowPage.apply(this, args);
            setTimeout(() => window.completePageProgress(), 100);
            return result;
        };
    }

    // ================================================
    // E-002: SMOOTH PAGE TRANSITIONS
    // ================================================

    const transitionStyles = document.createElement('style');
    transitionStyles.id = 'page-transition-styles';
    transitionStyles.textContent = `
        .page-transition-exit {
            animation: pageExit 0.2s ease-out forwards;
        }

        .page-transition-enter {
            animation: pageEnter 0.3s ease-out forwards;
        }

        @keyframes pageExit {
            from {
                opacity: 1;
                transform: translateY(0);
            }
            to {
                opacity: 0;
                transform: translateY(-10px);
            }
        }

        @keyframes pageEnter {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Reduce motion for accessibility */
        @media (prefers-reduced-motion: reduce) {
            .page-transition-exit,
            .page-transition-enter {
                animation: none !important;
            }
        }
    `;
    document.head.appendChild(transitionStyles);

    window.transitionPage = function (fromPage, toPage, callback) {
        const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

        if (prefersReducedMotion) {
            fromPage?.classList.add('hidden');
            toPage?.classList.remove('hidden');
            if (callback) {
                callback();
            }
            return;
        }

        if (fromPage) {
            fromPage.classList.add('page-transition-exit');
            setTimeout(() => {
                fromPage.classList.add('hidden');
                fromPage.classList.remove('page-transition-exit');
            }, 200);
        }

        setTimeout(
            () => {
                if (toPage) {
                    toPage.classList.remove('hidden');
                    toPage.classList.add('page-transition-enter');
                    setTimeout(() => {
                        toPage.classList.remove('page-transition-enter');
                        if (callback) {
                            callback();
                        }
                    }, 300);
                }
            },
            fromPage ? 200 : 0
        );
    };

    // ================================================
    // E-004: FILE TYPE ICONS
    // ================================================

    const fileTypeIcons = {
        // Documents
        pdf: { icon: 'fa-file-pdf', color: 'text-red-500' },
        doc: { icon: 'fa-file-word', color: 'text-blue-600' },
        docx: { icon: 'fa-file-word', color: 'text-blue-600' },
        odt: { icon: 'fa-file-word', color: 'text-blue-500' },
        rtf: { icon: 'fa-file-alt', color: 'text-gray-600' },
        txt: { icon: 'fa-file-alt', color: 'text-gray-500' },

        // Spreadsheets
        xls: { icon: 'fa-file-excel', color: 'text-green-600' },
        xlsx: { icon: 'fa-file-excel', color: 'text-green-600' },
        csv: { icon: 'fa-file-csv', color: 'text-green-500' },
        ods: { icon: 'fa-file-excel', color: 'text-green-500' },

        // Presentations
        ppt: { icon: 'fa-file-powerpoint', color: 'text-orange-500' },
        pptx: { icon: 'fa-file-powerpoint', color: 'text-orange-500' },
        odp: { icon: 'fa-file-powerpoint', color: 'text-orange-400' },

        // Images
        jpg: { icon: 'fa-file-image', color: 'text-purple-500' },
        jpeg: { icon: 'fa-file-image', color: 'text-purple-500' },
        png: { icon: 'fa-file-image', color: 'text-purple-500' },
        gif: { icon: 'fa-file-image', color: 'text-purple-500' },
        svg: { icon: 'fa-file-image', color: 'text-purple-400' },
        webp: { icon: 'fa-file-image', color: 'text-purple-500' },
        bmp: { icon: 'fa-file-image', color: 'text-purple-400' },

        // Video
        mp4: { icon: 'fa-file-video', color: 'text-pink-500' },
        avi: { icon: 'fa-file-video', color: 'text-pink-500' },
        mov: { icon: 'fa-file-video', color: 'text-pink-500' },
        mkv: { icon: 'fa-file-video', color: 'text-pink-500' },
        webm: { icon: 'fa-file-video', color: 'text-pink-400' },

        // Audio
        mp3: { icon: 'fa-file-audio', color: 'text-cyan-500' },
        wav: { icon: 'fa-file-audio', color: 'text-cyan-500' },
        ogg: { icon: 'fa-file-audio', color: 'text-cyan-500' },
        flac: { icon: 'fa-file-audio', color: 'text-cyan-400' },

        // Archives
        zip: { icon: 'fa-file-archive', color: 'text-amber-600' },
        rar: { icon: 'fa-file-archive', color: 'text-amber-600' },
        '7z': { icon: 'fa-file-archive', color: 'text-amber-600' },
        tar: { icon: 'fa-file-archive', color: 'text-amber-500' },
        gz: { icon: 'fa-file-archive', color: 'text-amber-500' },

        // Code
        js: { icon: 'fa-file-code', color: 'text-yellow-500' },
        ts: { icon: 'fa-file-code', color: 'text-blue-500' },
        html: { icon: 'fa-file-code', color: 'text-orange-500' },
        css: { icon: 'fa-file-code', color: 'text-blue-400' },
        json: { icon: 'fa-file-code', color: 'text-gray-600' },
        py: { icon: 'fa-file-code', color: 'text-green-500' },

        // Default
        default: { icon: 'fa-file', color: 'text-gray-400' },
    };

    window.getFileTypeIcon = function (filename) {
        const ext = filename.split('.').pop()?.toLowerCase() || '';
        return fileTypeIcons[ext] || fileTypeIcons.default;
    };

    window.createFileIcon = function (filename) {
        const { icon, color } = window.getFileTypeIcon(filename);
        return `<i class="fas ${icon} ${color}"></i>`;
    };

    // ================================================
    // E-005: SEARCH RESULTS HIGHLIGHTING
    // ================================================

    window.highlightMatches = function (text, query) {
        if (!query || query.length < 2) {
            return text;
        }

        const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`(${escapedQuery})`, 'gi');
        return text.replace(
            regex,
            '<mark class="highlight-match bg-yellow-200 dark:bg-yellow-600 px-0.5 rounded">$1</mark>'
        );
    };

    // Add highlight styles
    const highlightStyles = document.createElement('style');
    highlightStyles.textContent = `
        .highlight-match {
            background-color: #fef08a;
            padding: 0 2px;
            border-radius: 2px;
        }

        [data-theme="dark"] .highlight-match,
        .dark .highlight-match {
            background-color: #ca8a04;
            color: #fff;
        }
    `;
    document.head.appendChild(highlightStyles);

    // ================================================
    // E-006: RECENT FILES SECTION
    // ================================================

    const RecentFiles = {
        STORAGE_KEY: 'gcsemate_recent_files',
        MAX_FILES: 10,

        getRecentFiles() {
            try {
                const stored = localStorage.getItem(this.STORAGE_KEY);
                return stored ? JSON.parse(stored) : [];
            } catch {
                return [];
            }
        },

        addFile(file) {
            const files = this.getRecentFiles();

            // Remove duplicate if exists
            const filtered = files.filter(f => f.id !== file.id);

            // Add to beginning
            filtered.unshift({
                id: file.id,
                name: file.name,
                type: file.type,
                subject: file.subject,
                timestamp: Date.now(),
            });

            // Keep only MAX_FILES
            const trimmed = filtered.slice(0, this.MAX_FILES);

            try {
                localStorage.setItem(this.STORAGE_KEY, JSON.stringify(trimmed));
            } catch {
                // Storage might be full
            }

            return trimmed;
        },

        clearRecentFiles() {
            try {
                localStorage.removeItem(this.STORAGE_KEY);
            } catch {
                // Ignore errors
            }
        },
    };

    window.RecentFiles = RecentFiles;

    // ================================================
    // E-007: STUDY TIME TRACKING
    // ================================================

    const StudyTracker = {
        STORAGE_KEY: 'gcsemate_study_time',
        currentSubject: null,
        startTime: null,
        intervalId: null,

        start(subject) {
            this.stop(); // Stop any existing tracking
            this.currentSubject = subject;
            this.startTime = Date.now();

            // Update every minute
            this.intervalId = setInterval(() => {
                this.save();
            }, 60000);
        },

        stop() {
            if (this.currentSubject && this.startTime) {
                this.save();
            }
            this.currentSubject = null;
            this.startTime = null;
            if (this.intervalId) {
                clearInterval(this.intervalId);
                this.intervalId = null;
            }
        },

        save() {
            if (!this.currentSubject || !this.startTime) {
                return;
            }

            const duration = Date.now() - this.startTime;
            const today = new Date().toISOString().split('T')[0];

            try {
                const data = JSON.parse(localStorage.getItem(this.STORAGE_KEY) || '{}');

                if (!data[today]) {
                    data[today] = {};
                }

                if (!data[today][this.currentSubject]) {
                    data[today][this.currentSubject] = 0;
                }

                data[today][this.currentSubject] += duration;

                // Reset start time for next interval
                this.startTime = Date.now();

                // Keep only last 30 days
                const keys = Object.keys(data).sort();
                while (keys.length > 30) {
                    delete data[keys.shift()];
                }

                localStorage.setItem(this.STORAGE_KEY, JSON.stringify(data));
            } catch {
                // Storage might be full
            }
        },

        getStats(days = 7) {
            try {
                const data = JSON.parse(localStorage.getItem(this.STORAGE_KEY) || '{}');
                const stats = {};
                const cutoff = new Date();
                cutoff.setDate(cutoff.getDate() - days);

                Object.entries(data).forEach(([date, subjects]) => {
                    if (new Date(date) >= cutoff) {
                        Object.entries(subjects).forEach(([subject, time]) => {
                            stats[subject] = (stats[subject] || 0) + time;
                        });
                    }
                });

                return stats;
            } catch {
                return {};
            }
        },

        formatDuration(ms) {
            const hours = Math.floor(ms / 3600000);
            const minutes = Math.floor((ms % 3600000) / 60000);

            if (hours > 0) {
                return `${hours}h ${minutes}m`;
            }
            return `${minutes}m`;
        },
    };

    window.StudyTracker = StudyTracker;

    // Stop tracking on page hide
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            StudyTracker.stop();
        }
    });

    window.addEventListener('beforeunload', () => {
        StudyTracker.stop();
    });

    // ================================================
    // E-008: CONFETTI ANIMATION FOR ACHIEVEMENTS
    // ================================================

    window.triggerConfetti = function (options = {}) {
        const {
            particleCount = 100,
            spread = 70,
            origin = { x: 0.5, y: 0.6 },
            colors = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981'],
        } = options;

        const canvas = document.createElement('canvas');
        canvas.id = 'confetti-canvas';
        canvas.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 99999;
        `;
        document.body.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        const particles = [];

        // Create particles
        for (let i = 0; i < particleCount; i++) {
            particles.push({
                x: canvas.width * origin.x + (Math.random() - 0.5) * spread * 2,
                y: canvas.height * origin.y,
                vx: (Math.random() - 0.5) * 10,
                vy: Math.random() * -15 - 5,
                color: colors[Math.floor(Math.random() * colors.length)],
                size: Math.random() * 8 + 4,
                rotation: Math.random() * 360,
                rotationSpeed: (Math.random() - 0.5) * 10,
            });
        }

        let animationId;
        const gravity = 0.3;
        const friction = 0.99;

        /**
         *
         */
        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            let allDone = true;

            particles.forEach(p => {
                p.vy += gravity;
                p.vx *= friction;
                p.x += p.vx;
                p.y += p.vy;
                p.rotation += p.rotationSpeed;

                if (p.y < canvas.height + 50) {
                    allDone = false;

                    ctx.save();
                    ctx.translate(p.x, p.y);
                    ctx.rotate((p.rotation * Math.PI) / 180);
                    ctx.fillStyle = p.color;
                    ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size);
                    ctx.restore();
                }
            });

            if (!allDone) {
                animationId = requestAnimationFrame(animate);
            } else {
                canvas.remove();
            }
        }

        animate();

        // Cleanup after 5 seconds max
        setTimeout(() => {
            if (animationId) {
                cancelAnimationFrame(animationId);
            }
            canvas.remove();
        }, 5000);
    };

    // ================================================
    // E-009: SKELETON LOADING STATES
    // ================================================

    const skeletonStyles = document.createElement('style');
    skeletonStyles.textContent = `
        .skeleton {
            background: linear-gradient(90deg, #e5e7eb 25%, #f3f4f6 50%, #e5e7eb 75%);
            background-size: 200% 100%;
            animation: skeleton-loading 1.5s ease-in-out infinite;
            border-radius: 0.375rem;
        }

        [data-theme="dark"] .skeleton,
        .dark .skeleton {
            background: linear-gradient(90deg, #374151 25%, #4b5563 50%, #374151 75%);
            background-size: 200% 100%;
        }

        @keyframes skeleton-loading {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        .skeleton-text {
            height: 1rem;
            margin-bottom: 0.5rem;
        }

        .skeleton-text.w-3\\/4 { width: 75%; }
        .skeleton-text.w-1\\/2 { width: 50%; }
        .skeleton-text.w-1\\/4 { width: 25%; }

        .skeleton-avatar {
            width: 3rem;
            height: 3rem;
            border-radius: 50%;
        }

        .skeleton-card {
            padding: 1rem;
            border-radius: 0.75rem;
        }

        .skeleton-image {
            width: 100%;
            height: 12rem;
            border-radius: 0.5rem;
        }
    `;
    document.head.appendChild(skeletonStyles);

    window.createSkeleton = function (type = 'text', options = {}) {
        const div = document.createElement('div');
        div.className = `skeleton skeleton-${type}`;

        if (options.width) {
            div.style.width = options.width;
        }
        if (options.height) {
            div.style.height = options.height;
        }
        if (options.className) {
            div.className += ` ${options.className}`;
        }

        return div;
    };

    window.createCardSkeleton = function () {
        const card = document.createElement('div');
        card.className = 'skeleton-card bg-white dark:bg-gray-800 rounded-xl p-4';
        card.innerHTML = `
            <div class="flex items-center gap-3 mb-4">
                <div class="skeleton skeleton-avatar"></div>
                <div class="flex-1">
                    <div class="skeleton skeleton-text w-1/2"></div>
                    <div class="skeleton skeleton-text w-1/4"></div>
                </div>
            </div>
            <div class="skeleton skeleton-text"></div>
            <div class="skeleton skeleton-text w-3/4"></div>
            <div class="skeleton skeleton-text w-1/2"></div>
        `;
        return card;
    };

    // ================================================
    // E-010: COPY TO CLIPBOARD FEEDBACK
    // ================================================

    window.copyToClipboard = async function (text, element) {
        try {
            await navigator.clipboard.writeText(text);

            if (element) {
                const original = element.innerHTML;
                element.innerHTML = '<i class="fas fa-check text-green-500"></i> Copied!';
                element.classList.add('text-green-600');

                setTimeout(() => {
                    element.innerHTML = original;
                    element.classList.remove('text-green-600');
                }, 2000);
            }

            if (typeof showToast === 'function') {
                showToast('Copied to clipboard!', 'success', 2000);
            }

            return true;
        } catch (err) {
            if (typeof showToast === 'function') {
                showToast('Failed to copy', 'error');
            }
            return false;
        }
    };

    // ================================================
    // E-011: LAZY LOADING FOR IMAGES (Enhanced)
    // ================================================

    /**
     *
     */
    function setupLazyLoading() {
        // Add loading="lazy" to all images without it
        document.querySelectorAll('img:not([loading])').forEach(img => {
            // Don't lazy load above-the-fold images
            const rect = img.getBoundingClientRect();
            if (rect.top > window.innerHeight) {
                img.loading = 'lazy';
                img.decoding = 'async';
            }
        });

        // Use Intersection Observer for more control
        const lazyImages = document.querySelectorAll('img[data-src]');

        if (lazyImages.length === 0) {
            return;
        }

        const imageObserver = new IntersectionObserver(
            (entries, observer) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const img = entry.target;
                        img.src = img.dataset.src;
                        if (img.dataset.srcset) {
                            img.srcset = img.dataset.srcset;
                        }
                        img.classList.remove('lazy');
                        observer.unobserve(img);
                    }
                });
            },
            {
                rootMargin: '50px 0px',
            }
        );

        lazyImages.forEach(img => imageObserver.observe(img));
    }

    // ================================================
    // E-012: FORM AUTOSAVE
    // ================================================

    window.setupFormAutosave = function (formId, options = {}) {
        const form = document.getElementById(formId);
        if (!form) {
            return;
        }

        const saveKey = `draft_${formId}`;
        const { debounceMs = 1000, excludeFields = [] } = options;

        // Load existing draft
        /**
         *
         */
        function loadDraft() {
            try {
                const draft = localStorage.getItem(saveKey);
                if (!draft) {
                    return;
                }

                const data = JSON.parse(draft);
                Object.entries(data).forEach(([name, value]) => {
                    const input = form.elements[name];
                    if (input && !excludeFields.includes(name)) {
                        if (input.type === 'checkbox') {
                            input.checked = value;
                        } else if (input.type === 'radio') {
                            const radio = form.querySelector(
                                `input[name="${name}"][value="${value}"]`
                            );
                            if (radio) {
                                radio.checked = true;
                            }
                        } else {
                            input.value = value;
                        }
                    }
                });

                // Show indicator that draft was loaded
                if (typeof showToast === 'function') {
                    showToast('Draft restored', 'info', 2000);
                }
            } catch {
                // Ignore parse errors
            }
        }

        // Save draft
        /**
         *
         */
        function saveDraft() {
            const data = {};
            const formData = new FormData(form);

            for (const [name, value] of formData.entries()) {
                if (!excludeFields.includes(name)) {
                    data[name] = value;
                }
            }

            try {
                localStorage.setItem(saveKey, JSON.stringify(data));
            } catch {
                // Storage might be full
            }
        }

        // Clear draft on successful submit
        /**
         *
         */
        function clearDraft() {
            try {
                localStorage.removeItem(saveKey);
            } catch {
                // Ignore errors
            }
        }

        // Debounce save
        let saveTimeout;
        const debouncedSave = () => {
            clearTimeout(saveTimeout);
            saveTimeout = setTimeout(saveDraft, debounceMs);
        };

        // Add event listeners
        form.addEventListener('input', debouncedSave);
        form.addEventListener('change', debouncedSave);
        form.addEventListener('submit', clearDraft);

        // Load draft on init
        loadDraft();

        return {
            save: saveDraft,
            clear: clearDraft,
            load: loadDraft,
        };
    };

    // ================================================
    // E-013: DRAG AND DROP FILE UPLOAD
    // ================================================

    window.setupDropZone = function (elementId, options = {}) {
        const dropZone = document.getElementById(elementId);
        if (!dropZone) {
            return;
        }

        const {
            onFiles = () => {},
            accept = '*',
            multiple = true,
            maxSize = 10 * 1024 * 1024, // 10MB default
        } = options;

        // Add styles
        dropZone.classList.add('drop-zone');

        const dropZoneStyles = document.createElement('style');
        dropZoneStyles.textContent = `
            .drop-zone {
                border: 2px dashed #d1d5db;
                border-radius: 0.75rem;
                padding: 2rem;
                text-align: center;
                transition: all 0.2s ease;
                cursor: pointer;
            }

            .drop-zone:hover,
            .drop-zone.drag-over {
                border-color: #3b82f6;
                background-color: rgba(59, 130, 246, 0.05);
            }

            .drop-zone.drag-over {
                transform: scale(1.02);
            }

            [data-theme="dark"] .drop-zone {
                border-color: #4b5563;
            }

            [data-theme="dark"] .drop-zone:hover,
            [data-theme="dark"] .drop-zone.drag-over {
                border-color: #60a5fa;
                background-color: rgba(96, 165, 250, 0.1);
            }
        `;
        if (!document.getElementById('drop-zone-styles')) {
            dropZoneStyles.id = 'drop-zone-styles';
            document.head.appendChild(dropZoneStyles);
        }

        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(event => {
            dropZone.addEventListener(event, e => {
                e.preventDefault();
                e.stopPropagation();
            });
        });

        // Highlight on drag
        ['dragenter', 'dragover'].forEach(event => {
            dropZone.addEventListener(event, () => {
                dropZone.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach(event => {
            dropZone.addEventListener(event, () => {
                dropZone.classList.remove('drag-over');
            });
        });

        // Handle drop
        dropZone.addEventListener('drop', e => {
            const files = Array.from(e.dataTransfer.files);
            handleFiles(files);
        });

        // Handle click to upload
        dropZone.addEventListener('click', () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = accept;
            input.multiple = multiple;
            input.onchange = e => handleFiles(Array.from(e.target.files));
            input.click();
        });

        /**
         *
         */
        function handleFiles(files) {
            const validFiles = files.filter(file => {
                if (file.size > maxSize) {
                    if (typeof showToast === 'function') {
                        showToast(`File "${file.name}" is too large`, 'error');
                    }
                    return false;
                }
                return true;
            });

            if (validFiles.length > 0) {
                onFiles(multiple ? validFiles : [validFiles[0]]);
            }
        }

        return { handleFiles };
    };

    // ================================================
    // E-014: PULL TO REFRESH ON MOBILE
    // ================================================

    window.setupPullToRefresh = function (options = {}) {
        const {
            onRefresh = () => window.location.reload(),
            threshold = 80,
            resistance = 2.5,
        } = options;

        let startY = 0;
        let currentY = 0;
        let isPulling = false;
        let refreshIndicator = null;

        // Create refresh indicator
        /**
         *
         */
        function createIndicator() {
            const indicator = document.createElement('div');
            indicator.id = 'pull-refresh-indicator';
            indicator.className =
                'fixed top-0 left-1/2 -translate-x-1/2 z-[19999] opacity-0 transition-opacity';
            indicator.innerHTML = `
                <div class="mt-4 w-10 h-10 bg-white dark:bg-gray-800 rounded-full shadow-lg flex items-center justify-center">
                    <i class="fas fa-arrow-down text-blue-500 refresh-arrow"></i>
                </div>
            `;

            const style = document.createElement('style');
            style.textContent = `
                #pull-refresh-indicator .refresh-arrow {
                    transition: transform 0.2s ease;
                }
                #pull-refresh-indicator.ready .refresh-arrow {
                    transform: rotate(180deg);
                }
                #pull-refresh-indicator.refreshing .refresh-arrow {
                    animation: spin 1s linear infinite;
                }
                @keyframes spin {
                    from { transform: rotate(0deg); }
                    to { transform: rotate(360deg); }
                }
            `;
            document.head.appendChild(style);

            document.body.appendChild(indicator);
            return indicator;
        }

        refreshIndicator = createIndicator();

        document.addEventListener(
            'touchstart',
            e => {
                if (window.scrollY === 0) {
                    startY = e.touches[0].pageY;
                    isPulling = true;
                }
            },
            { passive: true }
        );

        document.addEventListener(
            'touchmove',
            e => {
                if (!isPulling) {
                    return;
                }

                currentY = e.touches[0].pageY;
                const pullDistance = (currentY - startY) / resistance;

                if (pullDistance > 0 && window.scrollY === 0) {
                    refreshIndicator.style.opacity = Math.min(pullDistance / threshold, 1);
                    refreshIndicator.style.transform = `translateX(-50%) translateY(${Math.min(pullDistance, threshold)}px)`;

                    if (pullDistance >= threshold) {
                        refreshIndicator.classList.add('ready');
                    } else {
                        refreshIndicator.classList.remove('ready');
                    }
                }
            },
            { passive: true }
        );

        document.addEventListener(
            'touchend',
            () => {
                if (!isPulling) {
                    return;
                }

                const pullDistance = (currentY - startY) / resistance;

                if (pullDistance >= threshold) {
                    refreshIndicator.classList.remove('ready');
                    refreshIndicator.classList.add('refreshing');
                    refreshIndicator.style.transform = 'translateX(-50%) translateY(60px)';

                    // Call refresh callback
                    Promise.resolve(onRefresh()).finally(() => {
                        refreshIndicator.style.opacity = '0';
                        refreshIndicator.classList.remove('refreshing');
                        refreshIndicator.style.transform = 'translateX(-50%) translateY(0)';
                    });
                } else {
                    refreshIndicator.style.opacity = '0';
                    refreshIndicator.style.transform = 'translateX(-50%) translateY(0)';
                }

                isPulling = false;
                startY = 0;
                currentY = 0;
            },
            { passive: true }
        );
    };

    // ================================================
    // E-015: COMMAND PALETTE
    // ================================================

    const CommandPalette = {
        isOpen: false,
        commands: [],
        element: null,

        register(command) {
            this.commands.push(command);
        },

        open() {
            if (this.isOpen) {
                return;
            }
            this.isOpen = true;
            this.render();
        },

        close() {
            if (!this.isOpen) {
                return;
            }
            this.isOpen = false;
            if (this.element) {
                this.element.remove();
                this.element = null;
            }
        },

        render() {
            this.element = document.createElement('div');
            this.element.id = 'command-palette';
            this.element.className =
                'fixed inset-0 z-[30000] flex items-start justify-center pt-[20vh] bg-black/50 backdrop-blur-sm';
            this.element.innerHTML = `
                <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
                    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
                        <input type="text" id="command-search" placeholder="Type a command or search..."
                               class="w-full bg-transparent border-none outline-none text-lg text-gray-900 dark:text-white placeholder-gray-400">
                    </div>
                    <div id="command-list" class="max-h-80 overflow-y-auto p-2">
                        ${this.renderCommands(this.commands)}
                    </div>
                    <div class="p-3 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-500 flex gap-4">
                        <span><kbd class="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">↑↓</kbd> Navigate</span>
                        <span><kbd class="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">Enter</kbd> Select</span>
                        <span><kbd class="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">Esc</kbd> Close</span>
                    </div>
                </div>
            `;

            document.body.appendChild(this.element);

            const searchInput = this.element.querySelector('#command-search');
            const commandList = this.element.querySelector('#command-list');

            // Focus input
            searchInput.focus();

            // Filter commands on input
            searchInput.addEventListener('input', e => {
                const query = e.target.value.toLowerCase();
                const filtered = this.commands.filter(
                    cmd =>
                        cmd.name.toLowerCase().includes(query) ||
                        (cmd.keywords && cmd.keywords.some(k => k.toLowerCase().includes(query)))
                );
                commandList.innerHTML = this.renderCommands(filtered);
                this.setupCommandListeners(commandList);
            });

            // Close on backdrop click
            this.element.addEventListener('click', e => {
                if (e.target === this.element) {
                    this.close();
                }
            });

            // Close on ESC
            const escHandler = e => {
                if (e.key === 'Escape') {
                    this.close();
                    document.removeEventListener('keydown', escHandler);
                }
            };
            document.addEventListener('keydown', escHandler);

            // Setup command click listeners
            this.setupCommandListeners(commandList);
        },

        renderCommands(commands) {
            if (commands.length === 0) {
                return '<div class="p-4 text-center text-gray-500">No commands found</div>';
            }

            return commands
                .map(
                    (cmd, index) => `
                <button data-command-index="${index}" class="w-full flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-left transition-colors">
                    <i class="fas ${cmd.icon || 'fa-terminal'} w-5 text-gray-400"></i>
                    <div class="flex-1">
                        <div class="text-gray-900 dark:text-white font-medium">${cmd.name}</div>
                        ${cmd.description ? `<div class="text-xs text-gray-500">${cmd.description}</div>` : ''}
                    </div>
                    ${cmd.shortcut ? `<kbd class="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded">${cmd.shortcut}</kbd>` : ''}
                </button>
            `
                )
                .join('');
        },

        setupCommandListeners(list) {
            list.querySelectorAll('[data-command-index]').forEach(btn => {
                btn.addEventListener('click', () => {
                    const index = parseInt(btn.dataset.commandIndex);
                    const filteredCommands = Array.from(
                        list.querySelectorAll('[data-command-index]')
                    ).map(b =>
                        this.commands.find((_, i) => i === parseInt(b.dataset.commandIndex))
                    );

                    const cmd = filteredCommands[index] || this.commands[index];
                    if (cmd && cmd.action) {
                        this.close();
                        cmd.action();
                    }
                });
            });
        },
    };

    // Register default commands
    CommandPalette.register({
        name: 'Toggle Dark Mode',
        icon: 'fa-moon',
        shortcut: 'T',
        keywords: ['theme', 'light', 'dark'],
        action: () => {
            const toggle = document.getElementById('theme-toggle');
            if (toggle) {
                toggle.click();
            }
        },
    });

    CommandPalette.register({
        name: 'Go to Dashboard',
        icon: 'fa-home',
        shortcut: 'G D',
        keywords: ['home', 'main'],
        action: () => {
            if (typeof showPage === 'function') {
                showPage('dashboard');
            }
        },
    });

    CommandPalette.register({
        name: 'Search Files',
        icon: 'fa-search',
        shortcut: '/',
        keywords: ['find', 'browse'],
        action: () => {
            const search = document.querySelector('#file-search-input, input[type="search"]');
            if (search) {
                search.focus();
            }
        },
    });

    CommandPalette.register({
        name: 'Print Page',
        icon: 'fa-print',
        shortcut: 'Ctrl+P',
        action: () => window.print(),
    });

    CommandPalette.register({
        name: 'Refresh Page',
        icon: 'fa-sync',
        shortcut: 'Ctrl+R',
        action: () => window.location.reload(),
    });

    window.CommandPalette = CommandPalette;

    // Open command palette with Ctrl+K or Cmd+K
    document.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            if (CommandPalette.isOpen) {
                CommandPalette.close();
            } else {
                CommandPalette.open();
            }
        }
    });

    // ================================================
    // INITIALIZATION
    // ================================================

    /**
     * Initialize all enhancements
     */
    function initEnhancements() {
        // Initialize DOM-dependent features
        initPageProgress();
        setupLazyLoading();

        // Only setup pull to refresh on mobile
        if ('ontouchstart' in window && window.innerWidth < 768) {
            // Disabled by default - can be enabled with: setupPullToRefresh()
        }

        log('Enhancement Features loaded successfully!');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initEnhancements);
    } else {
        initEnhancements();
    }
})();
