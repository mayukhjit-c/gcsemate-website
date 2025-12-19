/**
 * GCSEMate - Visual & UI Fixes
 * Addresses: V-001 to V-007, TR-001 to TR-005
 * Priority: HIGH (🟠)
 */

(function () {
    'use strict';

    console.log('🎨 Loading Visual & UI Fixes...');

    // ================================================
    // LAYOUT & POSITIONING FIXES
    // ================================================

    const layoutFixes = document.createElement('style');
    layoutFixes.id = 'layout-positioning-fixes';
    layoutFixes.textContent = `
        /* ========================================
           CRITICAL LAYOUT FIXES
           ======================================== */

        /* Fix body scroll lock without breaking layout */
        body.modal-open {
            overflow: hidden !important;
            /* Don't use position:fixed as it breaks layout */
        }

        /* Ensure proper page stacking */
        #page-container {
            position: relative;
            z-index: 1;
        }

        /* Fix pages showing behind each other */
        .page {
            display: none;
            position: relative;
            z-index: 1;
        }

        .page:not(.hidden) {
            display: block;
        }

        /* Ensure header is always visible and not cut off */
        header, nav, #main-nav {
            position: sticky !important;
            top: 0;
            z-index: 100;
            width: 100%;
        }

        /* Fix main content area */
        #page-content {
            position: relative;
            z-index: 1;
            min-height: calc(100vh - 80px);
            overflow-x: hidden;
        }

        /* Prevent element cutoff */
        .overflow-hidden {
            overflow: visible !important;
        }

        /* But keep scroll areas working */
        .overflow-y-auto {
            overflow-y: auto !important;
            overflow-x: hidden !important;
        }

        /* Fix flex containers */
        #app-container {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            overflow-x: hidden;
        }

        main#page-content {
            flex: 1;
            display: flex;
            flex-direction: column;
        }

        /* Ensure modals appear above everything */
        .fixed.inset-0 {
            z-index: 9999 !important;
        }

        /* ========================================
           VIBRANT COLOR PALETTE - LIGHT MODE
           ======================================== */

        /* Gradient backgrounds for main areas */
        body {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 25%, #f0fdf4 50%, #fdf4ff 75%, #fff7ed 100%) !important;
            background-attachment: fixed !important;
        }

        /* Colorful header gradient */
        header, #main-nav, nav.bg-white {
            background: linear-gradient(135deg, rgba(255,255,255,0.95), rgba(248,250,252,0.95)) !important;
            backdrop-filter: blur(20px) saturate(180%) !important;
            -webkit-backdrop-filter: blur(20px) saturate(180%) !important;
            border-bottom: 1px solid rgba(59, 130, 246, 0.1) !important;
            box-shadow: 0 4px 30px rgba(59, 130, 246, 0.08) !important;
        }

        /* Vibrant cards with gradient borders */
        .bg-white\\/70,
        .bg-white\\/80,
        .bg-white\\/90,
        [class*="bg-white/"] {
            background: linear-gradient(135deg, rgba(255,255,255,0.9), rgba(248,250,252,0.85)) !important;
            border: 1px solid transparent !important;
            background-clip: padding-box !important;
            position: relative;
        }

        .bg-white\\/70::before,
        .bg-white\\/80::before,
        .bg-white\\/90::before {
            content: '';
            position: absolute;
            inset: 0;
            border-radius: inherit;
            padding: 1px;
            background: linear-gradient(135deg, rgba(59,130,246,0.2), rgba(168,85,247,0.2), rgba(236,72,153,0.2));
            -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
            -webkit-mask-composite: xor;
            mask-composite: exclude;
            pointer-events: none;
        }

        /* Colorful stat cards */
        .bg-blue-50\\/70, .bg-blue-50 {
            background: linear-gradient(135deg, #dbeafe, #eff6ff) !important;
            border: 1px solid rgba(59, 130, 246, 0.3) !important;
        }

        .bg-purple-50\\/70, .bg-purple-50 {
            background: linear-gradient(135deg, #f3e8ff, #faf5ff) !important;
            border: 1px solid rgba(168, 85, 247, 0.3) !important;
        }

        .bg-green-50\\/70, .bg-green-50 {
            background: linear-gradient(135deg, #dcfce7, #f0fdf4) !important;
            border: 1px solid rgba(34, 197, 94, 0.3) !important;
        }

        .bg-amber-50\\/70, .bg-amber-50, .bg-yellow-50 {
            background: linear-gradient(135deg, #fef3c7, #fffbeb) !important;
            border: 1px solid rgba(245, 158, 11, 0.3) !important;
        }

        .bg-pink-50\\/70, .bg-pink-50 {
            background: linear-gradient(135deg, #fce7f3, #fdf2f8) !important;
            border: 1px solid rgba(236, 72, 153, 0.3) !important;
        }

        .bg-cyan-50\\/70, .bg-cyan-50 {
            background: linear-gradient(135deg, #cffafe, #ecfeff) !important;
            border: 1px solid rgba(6, 182, 212, 0.3) !important;
        }

        /* Vibrant primary buttons */
        .bg-blue-600 {
            background: linear-gradient(135deg, #3b82f6, #2563eb, #1d4ed8) !important;
            box-shadow: 0 4px 15px -3px rgba(59, 130, 246, 0.5), 0 0 0 1px rgba(59, 130, 246, 0.1) !important;
        }

        .bg-blue-600:hover {
            background: linear-gradient(135deg, #2563eb, #1d4ed8, #1e40af) !important;
            box-shadow: 0 6px 20px -3px rgba(59, 130, 246, 0.6), 0 0 0 1px rgba(59, 130, 246, 0.2) !important;
            transform: translateY(-1px);
        }

        /* Subject cards with colorful accents */
        #subject-grid > div,
        .subject-card {
            background: linear-gradient(135deg, rgba(255,255,255,0.95), rgba(248,250,252,0.9)) !important;
            border: none !important;
            box-shadow: 0 4px 20px -5px rgba(0,0,0,0.1), 0 0 0 1px rgba(59,130,246,0.08) !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }

        #subject-grid > div:hover,
        .subject-card:hover {
            transform: translateY(-4px) scale(1.02) !important;
            box-shadow: 0 12px 40px -10px rgba(59,130,246,0.25), 0 0 0 1px rgba(59,130,246,0.15) !important;
        }

        /* Animated gradient border on focus */
        input:focus, textarea:focus, select:focus {
            outline: none !important;
            border-color: transparent !important;
            box-shadow: 0 0 0 3px rgba(59,130,246,0.3), 0 0 0 1px #3b82f6 !important;
        }

        /* Colorful scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        ::-webkit-scrollbar-track {
            background: linear-gradient(180deg, #f1f5f9, #e2e8f0);
            border-radius: 5px;
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, #94a3b8, #64748b);
            border-radius: 5px;
            border: 2px solid #f1f5f9;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(180deg, #64748b, #475569);
        }

        /* Floating decorative elements */
        #page-content::before {
            content: '';
            position: fixed;
            top: 20%;
            left: -10%;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%);
            border-radius: 50%;
            pointer-events: none;
            z-index: -1;
        }

        #page-content::after {
            content: '';
            position: fixed;
            bottom: 10%;
            right: -5%;
            width: 300px;
            height: 300px;
            background: radial-gradient(circle, rgba(168,85,247,0.08) 0%, transparent 70%);
            border-radius: 50%;
            pointer-events: none;
            z-index: -1;
        }

        /* ========================================
           DARK MODE VIBRANT COLORS
           ======================================== */

        [data-theme="dark"] body {
            background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 25%, #172554 50%, #1e1b4b 75%, #0f172a 100%) !important;
        }

        [data-theme="dark"] header,
        [data-theme="dark"] #main-nav,
        [data-theme="dark"] nav {
            background: linear-gradient(135deg, rgba(30,41,59,0.95), rgba(15,23,42,0.95)) !important;
            border-bottom: 1px solid rgba(99, 102, 241, 0.2) !important;
            box-shadow: 0 4px 30px rgba(99, 102, 241, 0.1) !important;
        }

        [data-theme="dark"] .bg-blue-50\\/70,
        [data-theme="dark"] .bg-blue-50 {
            background: linear-gradient(135deg, rgba(30, 58, 138, 0.5), rgba(49, 46, 129, 0.4)) !important;
            border-color: rgba(99, 102, 241, 0.3) !important;
        }

        [data-theme="dark"] .bg-purple-50\\/70,
        [data-theme="dark"] .bg-purple-50 {
            background: linear-gradient(135deg, rgba(88, 28, 135, 0.4), rgba(49, 46, 129, 0.4)) !important;
            border-color: rgba(168, 85, 247, 0.3) !important;
        }

        [data-theme="dark"] .bg-green-50\\/70,
        [data-theme="dark"] .bg-green-50 {
            background: linear-gradient(135deg, rgba(20, 83, 45, 0.4), rgba(21, 128, 61, 0.3)) !important;
            border-color: rgba(34, 197, 94, 0.3) !important;
        }

        [data-theme="dark"] #page-content::before {
            background: radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 70%);
        }

        [data-theme="dark"] #page-content::after {
            background: radial-gradient(circle, rgba(168,85,247,0.15) 0%, transparent 70%);
        }

        [data-theme="dark"] ::-webkit-scrollbar-track {
            background: linear-gradient(180deg, #1e293b, #0f172a);
        }

        [data-theme="dark"] ::-webkit-scrollbar-thumb {
            background: linear-gradient(180deg, #475569, #334155);
            border-color: #1e293b;
        }

        /* ========================================
           MICRO-INTERACTIONS & POLISH
           ======================================== */

        /* Button press effect */
        button:active:not(:disabled),
        .btn:active:not(:disabled),
        a.btn:active {
            transform: scale(0.97) !important;
        }

        /* Card tilt on hover */
        .glass-card-premium,
        .modern-card,
        #subject-grid > div {
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1) !important;
            transform-style: preserve-3d;
        }

        /* Glowing border effect on hover */
        .glass-card-premium:hover,
        .modern-card:hover {
            box-shadow:
                0 20px 40px -15px rgba(59, 130, 246, 0.2),
                0 0 30px -10px rgba(168, 85, 247, 0.15),
                inset 0 0 0 1px rgba(255, 255, 255, 0.1) !important;
        }

        /* Ripple effect for buttons */
        button, .btn, a.btn {
            position: relative;
            overflow: hidden;
        }

        button::after, .btn::after, a.btn::after {
            content: '';
            position: absolute;
            width: 100%;
            height: 100%;
            top: 0;
            left: 0;
            pointer-events: none;
            background-image: radial-gradient(circle, rgba(255,255,255,0.3) 10%, transparent 10.01%);
            background-repeat: no-repeat;
            background-position: 50%;
            transform: scale(10, 10);
            opacity: 0;
            transition: transform 0.5s, opacity 0.5s;
        }

        button:active::after, .btn:active::after, a.btn:active::after {
            transform: scale(0, 0);
            opacity: 0.3;
            transition: 0s;
        }

        /* Input focus glow */
        input:focus, textarea:focus, select:focus {
            animation: inputGlow 1.5s ease-in-out infinite alternate;
        }

        @keyframes inputGlow {
            from {
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2), 0 0 0 1px #3b82f6;
            }
            to {
                box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.3), 0 0 0 1px #3b82f6;
            }
        }

        /* Animated gradient text for headings */
        h1, h2.text-2xl, h2.text-3xl {
            background: linear-gradient(135deg, #1e293b, #3b82f6, #8b5cf6, #1e293b);
            background-size: 300% 300%;
            -webkit-background-clip: text;
            background-clip: text;
            animation: gradientShift 8s ease infinite;
        }

        [data-theme="dark"] h1,
        [data-theme="dark"] h2.text-2xl,
        [data-theme="dark"] h2.text-3xl {
            background: linear-gradient(135deg, #f1f5f9, #60a5fa, #a78bfa, #f1f5f9);
            background-size: 300% 300%;
            -webkit-background-clip: text;
            background-clip: text;
        }

        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        /* Pulsing notification dot */
        .animate-pulse {
            animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite !important;
        }

        @keyframes pulse {
            0%, 100% {
                opacity: 1;
                transform: scale(1);
            }
            50% {
                opacity: 0.7;
                transform: scale(1.1);
            }
        }

        /* Hover lift effect for interactive elements */
        .hover-lift {
            transition: transform 0.3s ease, box-shadow 0.3s ease !important;
        }

        .hover-lift:hover {
            transform: translateY(-4px) !important;
            box-shadow: 0 12px 30px -10px rgba(0, 0, 0, 0.15) !important;
        }

        /* Icon spin on hover */
        button:hover i.fa-sync-alt,
        button:hover i.fa-refresh {
            animation: spin 0.8s ease;
        }

        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }

        /* Staggered fade in for grid items */
        #subject-grid > div,
        #file-list > div {
            animation: staggerFadeIn 0.5s ease forwards;
            opacity: 0;
        }

        #subject-grid > div:nth-child(1) { animation-delay: 0.05s; }
        #subject-grid > div:nth-child(2) { animation-delay: 0.1s; }
        #subject-grid > div:nth-child(3) { animation-delay: 0.15s; }
        #subject-grid > div:nth-child(4) { animation-delay: 0.2s; }
        #subject-grid > div:nth-child(5) { animation-delay: 0.25s; }
        #subject-grid > div:nth-child(6) { animation-delay: 0.3s; }
        #subject-grid > div:nth-child(7) { animation-delay: 0.35s; }
        #subject-grid > div:nth-child(8) { animation-delay: 0.4s; }

        @keyframes staggerFadeIn {
            from {
                opacity: 0;
                transform: translateY(20px) scale(0.95);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        /* Timer display glow when running */
        #study-timer-display {
            transition: all 0.3s ease;
        }

        .study-toggle-btn.running ~ * #study-timer-display,
        body.study-active #study-timer-display {
            color: #3b82f6 !important;
            text-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
        }

        /* Badge shimmer effect */
        .bg-blue-50, [class*="rounded-full"][class*="bg-"] {
            position: relative;
            overflow: hidden;
        }

        /* Progress bar gradient */
        .bg-blue-600[style*="width"] {
            background: linear-gradient(90deg, #3b82f6, #8b5cf6, #3b82f6) !important;
            background-size: 200% 100%;
            animation: progressShimmer 2s ease infinite;
        }

        @keyframes progressShimmer {
            0% { background-position: 100% 0; }
            100% { background-position: -100% 0; }
        }

        /* AI Tutor styles removed */
    `;

    document.head.appendChild(layoutFixes);

    // ================================================
    // STUDY SESSION BUTTON MERGE (Disabled - handled by functional-fixes.js)
    // ================================================

    // This function was causing conflicts with the StudyProgress system
    // The buttons now work via functional-fixes.js StudySessionFix
    function mergeStudyButtons() {
        // Disabled - functionality moved to functional-fixes.js
        return;

        /* Original code disabled
        const startBtn = document.getElementById('study-start-btn');
        const stopBtn = document.getElementById('study-stop-btn');

        if (!startBtn || !stopBtn) return;

        // Hide the stop button initially
        stopBtn.style.display = 'none';

        // Create a unified toggle button
        let isRunning = false;

        // Enhance start button to be a toggle
        startBtn.innerHTML = '<i class="fas fa-play"></i> Start Session';
        startBtn.classList.add('study-toggle-btn');

        // Style the button to change between start/stop
        const toggleStyles = document.createElement('style');
        toggleStyles.textContent = `
            .study-toggle-btn {
                min-width: 160px !important;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
            }

            .study-toggle-btn.running {
                background: linear-gradient(135deg, #ef4444, #dc2626, #b91c1c) !important;
                box-shadow: 0 4px 15px -3px rgba(239, 68, 68, 0.5) !important;
            }

            .study-toggle-btn.running:hover {
                background: linear-gradient(135deg, #dc2626, #b91c1c, #991b1b) !important;
                box-shadow: 0 6px 20px -3px rgba(239, 68, 68, 0.6) !important;
            }

            .study-toggle-btn i {
                transition: transform 0.3s ease;
            }

            .study-toggle-btn.running i {
                transform: scale(1.1);
            }
        `;
        document.head.appendChild(toggleStyles);

        // Override button click behavior
        const originalStartClick = startBtn.onclick;
        const originalStopClick = stopBtn.onclick;

        startBtn.addEventListener(
            'click',
            function (e) {
                e.preventDefault();
                e.stopPropagation();

                if (!isRunning) {
                    // Start session
                    isRunning = true;
                    startBtn.innerHTML = '<i class="fas fa-stop-circle"></i> Stop Session';
                    startBtn.classList.add('running');

                    // Trigger original start functionality
                    if (originalStartClick) {
                        originalStartClick.call(startBtn, e);
                    } else {
                        // Dispatch click on hidden stop btn's original behavior
                        stopBtn.style.display = 'none';
                        const startEvent = new MouseEvent('click', { bubbles: true });
                        // Manually trigger start
                        if (typeof window.startStudySession === 'function') {
                            window.startStudySession();
                        }
                    }
                } else {
                    // Stop session
                    isRunning = false;
                    startBtn.innerHTML = '<i class="fas fa-play"></i> Start Session';
                    startBtn.classList.remove('running');

                    // Trigger original stop functionality
                    if (originalStopClick) {
                        originalStopClick.call(stopBtn, e);
                    } else if (typeof window.stopStudySession === 'function') {
                        window.stopStudySession();
                    }
                }
            },
            true
        );

        // Watch for external changes to study state
        const timerDisplay = document.getElementById('study-timer-display');
        if (timerDisplay) {
            const observer = new MutationObserver(() => {
                const timerText = timerDisplay.textContent;
                const isTimerRunning = timerText && timerText !== '00:00:00';

                if (isTimerRunning && !isRunning) {
                    isRunning = true;
                    startBtn.innerHTML = '<i class="fas fa-stop-circle"></i> Stop Session';
                    startBtn.classList.add('running');
                } else if (!isTimerRunning && isRunning) {
                    isRunning = false;
                    startBtn.innerHTML = '<i class="fas fa-play"></i> Start Session';
                    startBtn.classList.remove('running');
                }
            });

            observer.observe(timerDisplay, { childList: true, characterData: true, subtree: true });
        }
        End of original code */
    }

    // ================================================
    // COMPREHENSIVE DARK MODE & COLOR FIXES (REMOVED FOR LIGHT MODE ONLY)
    // ================================================

    /* Dark mode fixes removed as per user request for light mode only interface */

    // ================================================
    // V-001: CONSISTENT BUTTON STYLES
    // ================================================

    const buttonStyles = document.createElement('style');
    buttonStyles.id = 'button-style-fixes';
    buttonStyles.textContent = `
        /* Unified button base styles */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            font-weight: 600;
            font-size: 0.9375rem;
            line-height: 1.25;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            border: none;
            text-decoration: none;
            gap: 0.5rem;
            min-height: 44px; /* Touch target size */
        }

        .btn:focus-visible {
            outline: 3px solid rgba(59, 130, 246, 0.5);
            outline-offset: 2px;
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        /* Size variants */
        .btn-xs { padding: 0.375rem 0.75rem; font-size: 0.75rem; min-height: 32px; }
        .btn-sm { padding: 0.5rem 1rem; font-size: 0.875rem; min-height: 36px; }
        .btn-lg { padding: 1rem 2rem; font-size: 1.125rem; min-height: 52px; }
        .btn-xl { padding: 1.25rem 2.5rem; font-size: 1.25rem; min-height: 60px; }

        /* Primary button */
        .btn-primary, .btn-gradient {
            background: linear-gradient(135deg, #3b82f6, #2563eb);
            color: white !important;
            box-shadow: 0 4px 12px -2px rgba(59, 130, 246, 0.35);
        }

        .btn-primary:hover, .btn-gradient:hover {
            background: linear-gradient(135deg, #2563eb, #1d4ed8);
            transform: translateY(-2px);
            box-shadow: 0 8px 20px -4px rgba(59, 130, 246, 0.45);
        }

        .btn-primary:active, .btn-gradient:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px -2px rgba(59, 130, 246, 0.3);
        }

        /* Secondary button */
        .btn-secondary {
            background: white;
            color: #374151 !important;
            border: 1px solid #e5e7eb;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
        }

        .btn-secondary:hover {
            background: #f9fafb;
            border-color: #d1d5db;
            transform: translateY(-1px);
        }

        /* Outline button */
        .btn-outline {
            background: transparent;
            color: #3b82f6 !important;
            border: 2px solid #3b82f6;
        }

        .btn-outline:hover {
            background: #eff6ff;
            transform: translateY(-1px);
        }

        /* Ghost button */
        .btn-ghost {
            background: transparent;
            color: #6b7280 !important;
        }

        .btn-ghost:hover {
            background: #f3f4f6;
            color: #374151 !important;
        }

        /* Danger button */
        .btn-danger {
            background: #ef4444;
            color: white !important;
        }

        .btn-danger:hover {
            background: #dc2626;
            transform: translateY(-1px);
        }

        /* Success button */
        .btn-success {
            background: #10b981;
            color: white !important;
        }

        .btn-success:hover {
            background: #059669;
            transform: translateY(-1px);
        }

        /* Icon button */
        .btn-icon {
            padding: 0.625rem;
            min-width: 44px;
            width: 44px;
            height: 44px;
        }

        .btn-icon.btn-sm {
            padding: 0.5rem;
            min-width: 36px;
            width: 36px;
            height: 36px;
        }

        /* Dark mode button adjustments */
        [data-theme="dark"] .btn-secondary {
            background: #334155;
            color: #f1f5f9 !important;
            border-color: #475569;
        }

        [data-theme="dark"] .btn-secondary:hover {
            background: #475569;
            border-color: #64748b;
        }

        [data-theme="dark"] .btn-ghost {
            color: #94a3b8 !important;
        }

        [data-theme="dark"] .btn-ghost:hover {
            background: #334155;
            color: #f1f5f9 !important;
        }

        [data-theme="dark"] .btn-outline {
            border-color: #60a5fa;
            color: #60a5fa !important;
        }

        [data-theme="dark"] .btn-outline:hover {
            background: rgba(59, 130, 246, 0.2);
        }
    `;

    document.head.appendChild(buttonStyles);

    // ================================================
    // V-002: RESTORE CARD SHADOWS
    // ================================================

    const cardStyles = document.createElement('style');
    cardStyles.id = 'card-style-fixes';
    cardStyles.textContent = `
        /* Restore subtle shadows to cards */
        .card-modern, .modern-card, .glass-card-premium {
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08),
                        0 1px 2px rgba(0, 0, 0, 0.04) !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .card-modern:hover, .modern-card:hover, .glass-card-premium:hover {
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1),
                        0 8px 10px -6px rgba(0, 0, 0, 0.08) !important;
            transform: translateY(-4px);
        }

        /* Card with colored accent */
        .card-accent-blue {
            border-left: 4px solid #3b82f6;
        }

        .card-accent-green {
            border-left: 4px solid #10b981;
        }

        .card-accent-purple {
            border-left: 4px solid #8b5cf6;
        }

        .card-accent-orange {
            border-left: 4px solid #f59e0b;
        }

        /* Dark mode card styles */
        [data-theme="dark"] .card-modern,
        [data-theme="dark"] .modern-card,
        [data-theme="dark"] .glass-card-premium,
        [data-theme="dark"] .glass-card {
            background-color: #1e293b !important;
            border-color: #334155 !important;
            box-shadow: 0 4px 20px -5px rgba(0, 0, 0, 0.4) !important;
        }

        [data-theme="dark"] .card-modern:hover,
        [data-theme="dark"] .modern-card:hover,
        [data-theme="dark"] .glass-card-premium:hover,
        [data-theme="dark"] .glass-card:hover {
            background-color: #334155 !important;
            box-shadow: 0 10px 40px -10px rgba(0, 0, 0, 0.5) !important;
        }
    `;

    document.head.appendChild(cardStyles);

    // ================================================
    // V-003: LOGO LOADING STATE
    // ================================================

    /**
     *
     */
    function fixLogoLoading() {
        document
            .querySelectorAll('img[src*="gcsemate"], img[alt*="GCSEMate"], img[alt*="Logo"]')
            .forEach(img => {
                if (img.dataset.loadingFixed) {
                    return;
                }

                // Add loading placeholder
                img.style.backgroundColor = '#e5e7eb';
                img.style.minWidth = '120px';
                img.style.minHeight = '40px';

                img.addEventListener('load', function () {
                    this.style.backgroundColor = 'transparent';
                });

                img.addEventListener('error', function () {
                    this.style.backgroundColor = '#fee2e2';
                });

                img.dataset.loadingFixed = 'true';
            });
    }

    // ================================================
    // V-004: WATERMARK OVERLAP FIX
    // ================================================

    const watermarkStyles = document.createElement('style');
    watermarkStyles.id = 'watermark-fixes';
    watermarkStyles.textContent = `
        /* Hide watermarks when modal is open */
        body.modal-open #site-watermark,
        body.modal-open #no-ai-badge {
            opacity: 0 !important;
            pointer-events: none !important;
        }

        /* Ensure watermarks don't block content */
        #site-watermark, #no-ai-badge {
            pointer-events: none;
            z-index: 50;
        }

        /* Hide on small screens to save space */
        @media (max-width: 640px) {
            #site-watermark {
                display: none;
            }
            #no-ai-badge {
                font-size: 0.625rem;
                opacity: 0.15 !important;
            }
        }
    `;

    document.head.appendChild(watermarkStyles);

    // ================================================
    // V-005: CONSISTENT BORDER RADIUS
    // ================================================

    const radiusStyles = document.createElement('style');
    radiusStyles.id = 'radius-fixes';
    radiusStyles.textContent = `
        :root {
            --radius-xs: 0.25rem;   /* 4px */
            --radius-sm: 0.375rem;  /* 6px */
            --radius-md: 0.5rem;    /* 8px */
            --radius-lg: 0.75rem;   /* 12px */
            --radius-xl: 1rem;      /* 16px */
            --radius-2xl: 1.5rem;   /* 24px */
            --radius-full: 9999px;
        }

        /* Apply consistent radius to common elements */
        .rounded-card { border-radius: var(--radius-xl); }
        .rounded-button { border-radius: var(--radius-lg); }
        .rounded-input { border-radius: var(--radius-md); }
        .rounded-badge { border-radius: var(--radius-sm); }
        .rounded-pill { border-radius: var(--radius-full); }
    `;

    document.head.appendChild(radiusStyles);

    // ================================================
    // V-006: UNIFIED EMPTY STATES
    // ================================================

    const emptyStateStyles = document.createElement('style');
    emptyStateStyles.id = 'empty-state-fixes';
    emptyStateStyles.textContent = `
        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 3rem 1.5rem;
            min-height: 200px;
        }

        .empty-state-icon {
            font-size: 3rem;
            color: #9ca3af;
            margin-bottom: 1rem;
            opacity: 0.6;
        }

        .empty-state-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: #374151;
            margin-bottom: 0.5rem;
        }

        .empty-state-text {
            font-size: 0.9375rem;
            color: #6b7280;
            max-width: 300px;
            line-height: 1.5;
        }

        .empty-state-action {
            margin-top: 1.5rem;
        }

        [data-theme="dark"] .empty-state-title { color: #f3f4f6; }
        [data-theme="dark"] .empty-state-text { color: #9ca3af; }
    `;

    document.head.appendChild(emptyStateStyles);

    // Helper to create empty state
    window.createEmptyState = function (options) {
        const {
            icon = 'fa-folder-open',
            title = 'Nothing here',
            text = '',
            action = null,
        } = options;

        return `
            <div class="empty-state">
                <i class="fas ${icon} empty-state-icon"></i>
                <h3 class="empty-state-title">${title}</h3>
                ${text ? `<p class="empty-state-text">${text}</p>` : ''}
                ${action ? `<div class="empty-state-action">${action}</div>` : ''}
            </div>
        `;
    };

    // ================================================
    // V-007: SUBJECT CARD COLORS
    // ================================================

    const subjectColors = {
        biology: { bg: 'from-green-50 to-emerald-50', border: 'border-green-200', icon: '#059669' },
        physics: { bg: 'from-amber-50 to-yellow-50', border: 'border-amber-200', icon: '#d97706' },
        chemistry: { bg: 'from-cyan-50 to-blue-50', border: 'border-cyan-200', icon: '#0891b2' },
        maths: { bg: 'from-blue-50 to-indigo-50', border: 'border-blue-200', icon: '#3b82f6' },
        mathematics: {
            bg: 'from-blue-50 to-indigo-50',
            border: 'border-blue-200',
            icon: '#3b82f6',
        },
        english: { bg: 'from-red-50 to-rose-50', border: 'border-red-200', icon: '#dc2626' },
        history: { bg: 'from-orange-50 to-amber-50', border: 'border-orange-200', icon: '#ea580c' },
        geography: { bg: 'from-teal-50 to-cyan-50', border: 'border-teal-200', icon: '#14b8a6' },
        'computer science': {
            bg: 'from-purple-50 to-violet-50',
            border: 'border-purple-200',
            icon: '#8b5cf6',
        },
        computing: {
            bg: 'from-purple-50 to-violet-50',
            border: 'border-purple-200',
            icon: '#8b5cf6',
        },
        music: { bg: 'from-pink-50 to-fuchsia-50', border: 'border-pink-200', icon: '#ec4899' },
        art: { bg: 'from-rose-50 to-pink-50', border: 'border-rose-200', icon: '#f43f5e' },
        'religious studies': {
            bg: 'from-indigo-50 to-purple-50',
            border: 'border-indigo-200',
            icon: '#6366f1',
        },
        re: { bg: 'from-indigo-50 to-purple-50', border: 'border-indigo-200', icon: '#6366f1' },
        french: { bg: 'from-blue-50 to-sky-50', border: 'border-blue-200', icon: '#0284c7' },
        spanish: { bg: 'from-orange-50 to-red-50', border: 'border-orange-200', icon: '#ea580c' },
        german: { bg: 'from-yellow-50 to-amber-50', border: 'border-yellow-200', icon: '#ca8a04' },
    };

    window.getSubjectColors = function (subjectName) {
        const normalizedName = subjectName.toLowerCase().trim();
        return (
            subjectColors[normalizedName] || {
                bg: 'from-gray-50 to-slate-50',
                border: 'border-gray-200',
                icon: '#6b7280',
            }
        );
    };

    // ================================================
    // TR-001: MOBILE FONT SIZE FIXES
    // ================================================

    const mobileTypography = document.createElement('style');
    mobileTypography.id = 'mobile-typography-fixes';
    mobileTypography.textContent = `
        /* Base font size adjustments for mobile */
        @media (max-width: 640px) {
            body {
                font-size: 16px;
                line-height: 1.6;
            }

            /* Minimum readable sizes */
            .text-xs { font-size: 0.8125rem !important; } /* 13px min */
            .text-sm { font-size: 0.875rem !important; }  /* 14px */

            /* Headings scale down gracefully */
            h1 { font-size: clamp(1.75rem, 6vw, 2.5rem); }
            h2 { font-size: clamp(1.5rem, 5vw, 2rem); }
            h3 { font-size: clamp(1.25rem, 4vw, 1.5rem); }
            h4 { font-size: clamp(1.125rem, 3.5vw, 1.25rem); }

            /* Card text */
            .card-modern p, .modern-card p {
                font-size: 0.9375rem;
                line-height: 1.6;
            }

            /* Button text */
            button, .btn {
                font-size: 0.9375rem;
            }
        }
    `;

    document.head.appendChild(mobileTypography);

    // ================================================
    // TR-002: PLACEHOLDER CONTRAST (already in accessibility)
    // TR-003: LINE HEIGHT IN CARDS
    // ================================================

    const lineHeightFixes = document.createElement('style');
    lineHeightFixes.id = 'line-height-fixes';
    lineHeightFixes.textContent = `
        /* Better line height for readability */
        .card-modern p, .modern-card p, .glass-card-premium p {
            line-height: 1.6;
            margin-bottom: 0.75rem;
        }

        .card-modern p:last-child, .modern-card p:last-child {
            margin-bottom: 0;
        }

        /* Improved list readability */
        ul li, ol li {
            line-height: 1.6;
            margin-bottom: 0.5rem;
        }
    `;

    document.head.appendChild(lineHeightFixes);

    // ================================================
    // TR-004: WORD OVERFLOW HANDLING
    // ================================================

    const wordWrapFixes = document.createElement('style');
    wordWrapFixes.id = 'word-wrap-fixes';
    wordWrapFixes.textContent = `
        /* Prevent long words/URLs from breaking layout */
        .break-words,
        .card-modern,
        .modern-card,
        p,
        td,
        th,
        li {
            word-wrap: break-word;
            overflow-wrap: break-word;
            hyphens: auto;
        }

        /* Special handling for emails and URLs */
        a[href^="mailto:"],
        a[href^="http"],
        .email,
        .url {
            word-break: break-all;
        }

        /* Prevent overflow in tables */
        table {
            table-layout: fixed;
            width: 100%;
        }

        td, th {
            overflow: hidden;
            text-overflow: ellipsis;
        }
    `;

    document.head.appendChild(wordWrapFixes);

    // ================================================
    // TR-005: BLOG CONTENT TYPOGRAPHY
    // ================================================

    const blogTypography = document.createElement('style');
    blogTypography.id = 'blog-typography-fixes';
    blogTypography.textContent = `
        .blog-content, .prose {
            font-size: 1.0625rem;
            line-height: 1.8;
            max-width: 65ch;
            margin: 0 auto;
            color: #374151;
        }

        .blog-content p, .prose p {
            margin-bottom: 1.5rem;
        }

        .blog-content h1, .prose h1 {
            font-size: 2rem;
            font-weight: 800;
            margin-top: 0;
            margin-bottom: 1.5rem;
            line-height: 1.2;
        }

        .blog-content h2, .prose h2 {
            font-size: 1.5rem;
            font-weight: 700;
            margin-top: 2.5rem;
            margin-bottom: 1rem;
            line-height: 1.3;
        }

        .blog-content h3, .prose h3 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-top: 2rem;
            margin-bottom: 0.75rem;
        }

        .blog-content ul, .prose ul,
        .blog-content ol, .prose ol {
            margin-bottom: 1.5rem;
            padding-left: 1.5rem;
        }

        .blog-content li, .prose li {
            margin-bottom: 0.5rem;
        }

        .blog-content blockquote, .prose blockquote {
            border-left: 4px solid #3b82f6;
            padding-left: 1rem;
            margin: 1.5rem 0;
            color: #4b5563;
            font-style: italic;
        }

        .blog-content code, .prose code {
            background: #f3f4f6;
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.875em;
        }

        .blog-content pre, .prose pre {
            background: #1f2937;
            color: #f9fafb;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            margin: 1.5rem 0;
        }

        .blog-content pre code, .prose pre code {
            background: transparent;
            padding: 0;
        }

        .blog-content img, .prose img {
            max-width: 100%;
            height: auto;
            border-radius: 0.5rem;
            margin: 1.5rem 0;
        }

        .blog-content a, .prose a {
            color: #2563eb;
            text-decoration: underline;
            text-underline-offset: 2px;
        }

        .blog-content a:hover, .prose a:hover {
            color: #1d4ed8;
        }

        [data-theme="dark"] .blog-content,
        [data-theme="dark"] .prose {
            color: #e5e7eb;
        }

        [data-theme="dark"] .blog-content code,
        [data-theme="dark"] .prose code {
            background: #374151;
        }
    `;

    document.head.appendChild(blogTypography);

    // ================================================
    // LOADING SPINNER ANIMATION
    // ================================================

    const spinnerStyles = document.createElement('style');
    spinnerStyles.id = 'spinner-fixes';
    spinnerStyles.textContent = `
        .loader, .spinner {
            border: 3px solid rgba(59, 130, 246, 0.2);
            border-top-color: #3b82f6;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            animation: spin 0.8s linear infinite;
            display: inline-block;
            vertical-align: middle;
        }

        .loader-sm { width: 16px; height: 16px; border-width: 2px; }
        .loader-lg { width: 32px; height: 32px; border-width: 4px; }
        .loader-xl { width: 48px; height: 48px; border-width: 4px; }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    `;

    document.head.appendChild(spinnerStyles);

    // ================================================
    // APPLY VISUAL FIXES
    // ================================================

    /**
     *
     */
    function applyVisualFixes() {
        fixLogoLoading();
        mergeStudyButtons();
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyVisualFixes);
    } else {
        applyVisualFixes();
    }

    // Also try after a short delay for dynamically loaded content
    setTimeout(mergeStudyButtons, 1000);
    setTimeout(mergeStudyButtons, 3000);

    // Re-apply on dynamic content
    const visualObserver = new MutationObserver(function (mutations) {
        mutations.forEach(mutation => {
            if (mutation.addedNodes.length > 0) {
                fixLogoLoading();
            }
        });
    });

    visualObserver.observe(document.body, { childList: true, subtree: true });

    // ================================================
    // FIX: SCROLL TO TOP BUTTON - Make it small and circular
    // ================================================

    const scrollTopFix = document.createElement('style');
    scrollTopFix.id = 'scroll-top-fix';
    scrollTopFix.textContent = `
        #scroll-top {
            /* Override to be a small circular button */
            width: 44px !important;
            height: 44px !important;
            min-width: 44px !important;
            min-height: 44px !important;
            max-width: 44px !important;
            max-height: 44px !important;
            padding: 0 !important;
            border-radius: 50% !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15) !important;
            opacity: 0.9;
            transition: opacity 0.2s, transform 0.2s !important;
        }

        #scroll-top:hover {
            opacity: 1;
            transform: scale(1.1);
        }

        #scroll-top svg {
            width: 20px !important;
            height: 20px !important;
        }

        @media (max-width: 640px) {
            #scroll-top {
                width: 40px !important;
                height: 40px !important;
                min-width: 40px !important;
                min-height: 40px !important;
                max-width: 40px !important;
                max-height: 40px !important;
                bottom: 16px !important;
                right: 16px !important;
            }

            #scroll-top svg {
                width: 18px !important;
                height: 18px !important;
            }
        }
    `;
    document.head.appendChild(scrollTopFix);

    // ================================================
    // FIX: HEADER LOGO OVERLAP
    // ================================================

    const headerLogoFix = document.createElement('style');
    headerLogoFix.id = 'header-logo-fix';
    headerLogoFix.textContent = `
        /* Prevent logo from overlapping header elements */
        header .flex-shrink-0 {
            z-index: 1;
            position: relative;
        }

        header .flex-shrink-0 img {
            max-width: 100px !important;
            height: auto !important;
            max-height: 36px !important;
        }

        @media (min-width: 640px) {
            header .flex-shrink-0 img {
                max-width: 120px !important;
                max-height: 40px !important;
            }
        }

        /* Ensure nav doesn't get covered */
        header nav {
            z-index: 2;
            position: relative;
        }

        /* Ensure header items are properly spaced */
        header {
            gap: 8px !important;
        }

        @media (min-width: 640px) {
            header {
                gap: 12px !important;
            }
        }
    `;
    document.head.appendChild(headerLogoFix);

    // ================================================
    // FIX: DARK MODE TEXT CONTRAST (REMOVED FOR LIGHT MODE ONLY)
    // ================================================

    /* Dark mode contrast fixes removed */

    // ================================================
    // REMOVE DARK MODE FEATURE ENTIRELY
    // ================================================

    const removeDarkMode = document.createElement('style');
    removeDarkMode.id = 'remove-dark-mode';
    removeDarkMode.textContent = `
        /* Hide all dark mode toggles */
        #theme-toggle,
        #theme-toggle-mobile,
        [id*="theme-toggle"],
        button[aria-label*="dark mode"],
        button[title*="Toggle theme"] {
            display: none !important;
        }

        /* Force light mode on all dark mode elements */
        .dark,
        [data-theme="dark"],
        body.dark-mode {
            --bg-primary: #f8fafc !important;
            --bg-card: #ffffff !important;
            --text-primary: #1f2937 !important;
            --text-secondary: #4b5563 !important;
            color-scheme: light !important;
        }

        /* Override any dark:* Tailwind classes */
        .dark\\:bg-gray-800,
        .dark\\:bg-gray-900,
        .dark\\:bg-slate-800,
        .dark\\:bg-slate-900 {
            background-color: #ffffff !important;
        }

        .dark\\:text-white,
        .dark\\:text-gray-100,
        .dark\\:text-gray-200,
        .dark\\:text-gray-300 {
            color: #1f2937 !important;
        }

        .dark\\:border-gray-600,
        .dark\\:border-gray-700 {
            border-color: #e5e7eb !important;
        }
    `;
    document.head.appendChild(removeDarkMode);

    // Remove dark mode from body if present
    function enforceLightMode() {
        document.body.classList.remove('dark', 'dark-mode');
        document.documentElement.classList.remove('dark', 'dark-mode');
        document.documentElement.removeAttribute('data-theme');
        localStorage.removeItem('theme');
        localStorage.removeItem('darkMode');
    }

    enforceLightMode();

    // Also observe for any dark mode additions
    const darkModeObserver = new MutationObserver(() => {
        if (
            document.body.classList.contains('dark') ||
            document.documentElement.classList.contains('dark') ||
            document.documentElement.getAttribute('data-theme') === 'dark'
        ) {
            enforceLightMode();
        }
    });
    darkModeObserver.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['class', 'data-theme'],
    });
    darkModeObserver.observe(document.body, { attributes: true, attributeFilter: ['class'] });

    // ================================================
    // LIGHT MODE FLASHCARD & STUDY PLANNER MODALS
    // ================================================

    const lightModeModals = document.createElement('style');
    lightModeModals.id = 'light-mode-modals';
    lightModeModals.textContent = `
        /* Flashcard Modal - Light Mode */
        #flashcard-modal > div,
        #flashcard-modal .bg-gray-800,
        #flashcard-modal [class*="dark:bg-gray-"] {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%) !important;
            color: #1f2937 !important;
            border: 1px solid #e5e7eb !important;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.15) !important;
        }

        #flashcard-modal input,
        #flashcard-modal textarea,
        #flashcard-modal select {
            background-color: #ffffff !important;
            color: #1f2937 !important;
            border-color: #d1d5db !important;
        }

        #flashcard-modal input:focus,
        #flashcard-modal textarea:focus,
        #flashcard-modal select:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15) !important;
        }

        #flashcard-modal label,
        #flashcard-modal h3,
        #flashcard-modal .text-gray-300,
        #flashcard-modal .text-gray-400 {
            color: #374151 !important;
        }

        #flashcard-modal .border-gray-700,
        #flashcard-modal .border-gray-600 {
            border-color: #e5e7eb !important;
        }

        /* Study Plan Modal - Light Mode */
        #study-plan-modal > div,
        #study-plan-modal .bg-gray-800,
        #study-plan-modal [class*="dark:bg-gray-"] {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%) !important;
            color: #1f2937 !important;
            border: 1px solid #e5e7eb !important;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.15) !important;
        }

        #study-plan-modal input,
        #study-plan-modal textarea,
        #study-plan-modal select {
            background-color: #ffffff !important;
            color: #1f2937 !important;
            border-color: #d1d5db !important;
        }

        #study-plan-modal input:focus,
        #study-plan-modal textarea:focus,
        #study-plan-modal select:focus {
            border-color: #3b82f6 !important;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15) !important;
        }

        #study-plan-modal label,
        #study-plan-modal h2,
        #study-plan-modal h3,
        #study-plan-modal .text-gray-300,
        #study-plan-modal .text-gray-400 {
            color: #374151 !important;
        }

        #study-plan-modal .border-gray-700,
        #study-plan-modal .border-gray-600 {
            border-color: #e5e7eb !important;
        }

        #study-plan-modal .bg-gray-700 {
            background-color: #f3f4f6 !important;
            color: #374151 !important;
        }

        #study-plan-modal .bg-gray-700:hover {
            background-color: #e5e7eb !important;
        }

        /* Practice Question Modal - Light Mode */
        #practice-question-modal > div,
        #practice-question-modal .bg-gray-800 {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%) !important;
            color: #1f2937 !important;
            border: 1px solid #e5e7eb !important;
        }

        /* All feature modals - consistent light mode */
        #note-editor-modal > div,
        #study-group-modal > div,
        #achievement-modal > div,
        #timetable-modal > div,
        #past-paper-modal > div,
        #voice-note-modal > div,
        #export-modal > div {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%) !important;
            color: #1f2937 !important;
            border: 1px solid #e5e7eb !important;
        }
    `;
    document.head.appendChild(lightModeModals);

    // ================================================
    // BLOG POST RIBBON BUTTONS FIX
    // ================================================

    const blogRibbonFix = document.createElement('style');
    blogRibbonFix.id = 'blog-ribbon-fix';
    blogRibbonFix.textContent = `
        /* Blog viewer toolbar/ribbon - consistent button styling */
        #blog-viewer-modal .flex.items-center.gap-2 button,
        #blog-viewer-modal [class*="flex"] > button {
            min-width: 80px !important;
            min-height: 36px !important;
            padding: 0.5rem 1rem !important;
            font-size: 0.875rem !important;
            font-weight: 600 !important;
            border-radius: 0.5rem !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            gap: 0.5rem !important;
            transition: all 0.2s ease !important;
        }

        /* Primary action buttons */
        #blog-viewer-modal button.bg-blue-600,
        #blog-viewer-modal button[class*="bg-blue"] {
            background: linear-gradient(135deg, #3b82f6, #2563eb) !important;
            color: white !important;
            border: none !important;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3) !important;
        }

        #blog-viewer-modal button.bg-blue-600:hover,
        #blog-viewer-modal button[class*="bg-blue"]:hover {
            background: linear-gradient(135deg, #2563eb, #1d4ed8) !important;
            transform: translateY(-1px) !important;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4) !important;
        }

        /* Secondary/gray buttons */
        #blog-viewer-modal button.bg-gray-100,
        #blog-viewer-modal button.bg-gray-200,
        #blog-viewer-modal button[class*="bg-gray-1"],
        #blog-viewer-modal button[class*="bg-gray-2"] {
            background: linear-gradient(135deg, #f3f4f6, #e5e7eb) !important;
            color: #374151 !important;
            border: 1px solid #d1d5db !important;
        }

        #blog-viewer-modal button.bg-gray-100:hover,
        #blog-viewer-modal button.bg-gray-200:hover {
            background: linear-gradient(135deg, #e5e7eb, #d1d5db) !important;
            border-color: #9ca3af !important;
        }

        /* Close button styling */
        #blog-viewer-modal button[onclick*="Close"],
        #blog-viewer-modal .text-2xl.font-bold {
            min-width: 36px !important;
            min-height: 36px !important;
            padding: 0.25rem !important;
            border-radius: 50% !important;
            background: #f3f4f6 !important;
            color: #6b7280 !important;
            font-size: 1.25rem !important;
            border: 1px solid #e5e7eb !important;
        }

        #blog-viewer-modal button[onclick*="Close"]:hover,
        #blog-viewer-modal .text-2xl.font-bold:hover {
            background: #e5e7eb !important;
            color: #1f2937 !important;
        }

        /* Button row alignment */
        #blog-viewer-modal .flex.items-center.gap-2 {
            display: flex !important;
            align-items: center !important;
            justify-content: flex-start !important;
            gap: 0.75rem !important;
            flex-wrap: wrap !important;
        }
    `;
    document.head.appendChild(blogRibbonFix);

    // ================================================
    // SEARCH ICONS ALIGNMENT FIX
    // ================================================

    const searchIconsFix = document.createElement('style');
    searchIconsFix.id = 'search-icons-fix';
    searchIconsFix.textContent = `
        /* Links search icon alignment */
        #links-search-input {
            padding-left: 2.5rem !important;
        }

        .relative:has(#links-search-input) .fa-search,
        .relative:has(#links-search-input) i.fa-search {
            position: absolute !important;
            left: 0.75rem !important;
            top: 50% !important;
            transform: translateY(-50%) !important;
            pointer-events: none !important;
            z-index: 1 !important;
        }

        /* File browser search icon alignment */
        #file-search-input {
            padding-left: 2.75rem !important;
        }

        #file-browser-controls .relative svg,
        .relative:has(#file-search-input) svg {
            position: absolute !important;
            left: 0.875rem !important;
            top: 50% !important;
            transform: translateY(-50%) !important;
            pointer-events: none !important;
            z-index: 1 !important;
        }

        /* Ensure relative container is properly positioned */
        .relative:has(input[type="search"]),
        .relative:has(#links-search-input),
        .relative:has(#file-search-input) {
            position: relative !important;
            display: flex !important;
            align-items: center !important;
        }

        /* Consistent search input styling */
        #links-search-input,
        #file-search-input {
            height: 40px !important;
            line-height: 40px !important;
        }
    `;
    document.head.appendChild(searchIconsFix);

    // ================================================
    // PRACTICE QUESTIONS PAGE - LIGHT MODE UI
    // ================================================

    const practiceQuestionsStyles = document.createElement('style');
    practiceQuestionsStyles.id = 'practice-questions-styles';
    practiceQuestionsStyles.textContent = `
        /* Practice Questions Page - Light Mode Styling */
        #practice-questions-page {
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%) !important;
        }

        #practice-questions-page .bg-gray-800,
        #practice-questions-page [class*="dark:bg-gray-"] {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%) !important;
        }

        #practice-questions-page h2,
        #practice-questions-page h3,
        #practice-questions-page h4,
        #practice-questions-page .text-gray-100,
        #practice-questions-page .text-gray-200,
        #practice-questions-page [class*="dark:text-gray-"] {
            color: #1f2937 !important;
        }

        #practice-questions-page p,
        #practice-questions-page span,
        #practice-questions-page .text-gray-300,
        #practice-questions-page .text-gray-400 {
            color: #4b5563 !important;
        }

        #practice-questions-page input,
        #practice-questions-page select,
        #practice-questions-page textarea {
            background-color: #ffffff !important;
            color: #1f2937 !important;
            border-color: #d1d5db !important;
        }

        #practice-questions-page .border-gray-600,
        #practice-questions-page .border-gray-700 {
            border-color: #e5e7eb !important;
        }

        /* Question cards */
        #practice-questions-content .border {
            background: #ffffff !important;
            border-color: #e5e7eb !important;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) !important;
        }

        /* Answer buttons */
        #practice-questions-content button[onclick*="answerQuestion"] {
            background: #ffffff !important;
            color: #374151 !important;
            border: 1px solid #d1d5db !important;
        }

        #practice-questions-content button[onclick*="answerQuestion"]:hover {
            background: #eff6ff !important;
            border-color: #3b82f6 !important;
        }

        /* Practice questions empty state */
        #practice-questions-content:empty::after {
            content: "Generate questions to start practicing!";
            display: block;
            text-align: center;
            padding: 3rem;
            color: #6b7280;
            font-size: 1rem;
        }
    `;
    document.head.appendChild(practiceQuestionsStyles);

    console.log('✅ Visual & UI Fixes loaded successfully!');
})();
