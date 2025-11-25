/**
 * GCSEMate - Mobile & Responsive Fixes
 * Addresses: MR-001 to MR-007
 * Priority: HIGH (🔴 to 🟠)
 */

(function () {
    'use strict';

    // Debug logging - silent in production
    const DEBUG = false;
    const log = DEBUG
        ? Function.prototype.bind.call(console.log, console, '📱 [Mobile]')
        : () => {}; // eslint-disable-line no-console

    log('Loading Mobile & Responsive Fixes...');

    const mobileStyles = document.createElement('style');
    mobileStyles.id = 'mobile-responsive-fixes';
    mobileStyles.textContent = `
        /* ================================================ */
        /* MR-001: NAVIGATION BREAKPOINT FIX */
        /* ================================================ */

        /* Hide desktop nav earlier to prevent overflow */
        @media (max-width: 1023px) {
            .desktop-nav,
            nav.hidden.lg\\:flex,
            .lg\\:flex.hidden {
                display: none !important;
            }

            .mobile-menu-button,
            #hamburger-button,
            button[aria-label*="menu"] {
                display: flex !important;
            }
        }

        @media (min-width: 1024px) {
            .desktop-nav,
            nav.hidden.lg\\:flex {
                display: flex !important;
            }

            .mobile-menu-button,
            #hamburger-button {
                display: none !important;
            }
        }

        /* ================================================ */
        /* MR-002: TOUCH TARGET SIZE (44x44px minimum) */
        /* ================================================ */

        button,
        a,
        [role="button"],
        input[type="button"],
        input[type="submit"],
        input[type="reset"],
        .clickable,
        .tappable {
            min-height: 44px;
            min-width: 44px;
        }

        /* Exceptions for inline elements */
        p a,
        span a,
        li a:not(.btn):not(.button),
        .inline-link {
            min-height: auto;
            min-width: auto;
            padding: 0.25rem 0;
        }

        /* Icon buttons */
        button:has(> i:only-child),
        button:has(> svg:only-child),
        a:has(> i:only-child),
        a:has(> svg:only-child) {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 44px;
            min-height: 44px;
            padding: 0.5rem;
        }

        /* Smaller tap targets allowed on larger screens */
        @media (min-width: 1024px) {
            button,
            a,
            [role="button"] {
                min-height: 32px;
                min-width: 32px;
            }
        }

        /* ================================================ */
        /* MR-003: MOBILE MENU BACK BUTTON */
        /* ================================================ */

        .mobile-menu-back {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1rem;
            width: 100%;
            text-align: left;
            background: #f3f4f6;
            border: none;
            font-weight: 500;
            color: #374151;
        }

        .mobile-menu-back:hover {
            background: #e5e7eb;
        }

        /* ================================================ */
        /* MR-004: TABLE RESPONSIVE OVERFLOW */
        /* ================================================ */

        .table-wrapper,
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            scrollbar-width: thin;
            max-width: 100%;
        }

        .table-wrapper::-webkit-scrollbar {
            height: 6px;
        }

        .table-wrapper::-webkit-scrollbar-thumb {
            background: #cbd5e1;
            border-radius: 3px;
        }

        table {
            min-width: 100%;
        }

        /* Mobile-friendly table styles */
        @media (max-width: 640px) {
            /* Option 1: Horizontal scroll indicator */
            .table-wrapper::after {
                content: '';
                position: absolute;
                right: 0;
                top: 0;
                bottom: 0;
                width: 40px;
                background: linear-gradient(to right, transparent, rgba(255,255,255,0.9));
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.3s;
            }

            .table-wrapper.has-scroll::after {
                opacity: 1;
            }

            /* Smaller table text on mobile */
            td, th {
                padding: 0.5rem 0.75rem;
                font-size: 0.875rem;
            }
        }

        /* ================================================ */
        /* MR-005: PREVENT iOS INPUT ZOOM */
        /* ================================================ */

        /* iOS zooms inputs with font-size < 16px */
        @media screen and (-webkit-min-device-pixel-ratio: 0) and (max-width: 767px) {
            input[type="text"],
            input[type="email"],
            input[type="password"],
            input[type="number"],
            input[type="tel"],
            input[type="url"],
            input[type="search"],
            input[type="date"],
            input[type="time"],
            input[type="datetime-local"],
            textarea,
            select {
                font-size: 16px !important;
            }
        }

        /* Ensure inputs are comfortable on touch */
        @media (max-width: 640px) {
            input,
            textarea,
            select {
                min-height: 48px;
                padding: 0.75rem 1rem;
            }
        }

        /* ================================================ */
        /* MR-006: LANDSCAPE ORIENTATION FIXES */
        /* ================================================ */

        @media (orientation: landscape) and (max-height: 500px) {
            /* Reduce header height in landscape */
            header {
                padding-top: 0.5rem;
                padding-bottom: 0.5rem;
            }

            header img {
                max-height: 32px;
            }

            /* Reduce page padding */
            .page {
                padding-top: 0.5rem;
                padding-bottom: 0.5rem;
            }

            /* Modals should be more compact */
            .fixed.inset-0 > div {
                max-height: 90vh;
                overflow-y: auto;
            }

            /* Hide non-essential elements */
            #site-watermark,
            #no-ai-badge {
                display: none !important;
            }
        }

        /* ================================================ */
        /* MR-007: SAFE AREA INSETS (Notch/Home indicator) */
        /* ================================================ */

        /* Apply safe area to fixed elements */
        header,
        .fixed.top-0 {
            padding-top: max(1rem, env(safe-area-inset-top, 0));
        }

        .fixed.bottom-0,
        footer.fixed {
            padding-bottom: max(1rem, env(safe-area-inset-bottom, 0));
        }

        .fixed.left-0 {
            padding-left: env(safe-area-inset-left, 0);
        }

        .fixed.right-0 {
            padding-right: env(safe-area-inset-right, 0);
        }

        /* Full-screen modals should respect safe areas */
        .fixed.inset-0 {
            padding: env(safe-area-inset-top, 0) env(safe-area-inset-right, 0)
                     env(safe-area-inset-bottom, 0) env(safe-area-inset-left, 0);
        }

        /* Bottom navigation/toolbar safe area */
        .bottom-bar,
        .bottom-nav,
        [data-bottom-bar] {
            padding-bottom: calc(1rem + env(safe-area-inset-bottom, 0));
        }

        /* ================================================ */
        /* ADDITIONAL MOBILE OPTIMIZATIONS */
        /* ================================================ */

        /* Prevent horizontal scroll */
        html, body {
            overflow-x: hidden;
            max-width: 100vw;
        }

        /* Better touch feedback */
        @media (hover: none) and (pointer: coarse) {
            button:active,
            a:active,
            [role="button"]:active {
                opacity: 0.7;
                transform: scale(0.98);
            }
        }

        /* Disable hover effects on touch devices */
        @media (hover: none) {
            button:hover,
            a:hover,
            .card-modern:hover,
            .modern-card:hover {
                transform: none !important;
            }
        }

        /* Smooth momentum scrolling */
        .scrollable,
        .overflow-auto,
        .overflow-y-auto,
        .overflow-x-auto {
            -webkit-overflow-scrolling: touch;
        }

        /* Mobile-first grid adjustments */
        @media (max-width: 640px) {
            .grid {
                gap: 0.75rem;
            }

            .grid-cols-2,
            .grid-cols-3,
            .grid-cols-4 {
                grid-template-columns: 1fr;
            }

            .sm\\:grid-cols-2 {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        /* Cards stack on mobile */
        @media (max-width: 640px) {
            .card-modern,
            .modern-card,
            .glass-card-premium {
                margin-left: 0;
                margin-right: 0;
            }
        }

        /* Modal adjustments for small screens */
        @media (max-width: 640px) {
            .fixed.inset-0 > div {
                margin: 0.5rem;
                max-height: calc(100vh - 1rem);
                max-width: calc(100vw - 1rem);
                border-radius: 1rem;
            }

            /* Full-screen modals on very small screens */
            @media (max-height: 600px) {
                .fixed.inset-0 > div {
                    margin: 0;
                    border-radius: 0;
                    max-height: 100vh;
                    max-width: 100vw;
                    height: 100%;
                    width: 100%;
                }
            }
        }

        /* Breadcrumb horizontal scroll on mobile */
        @media (max-width: 640px) {
            .breadcrumb,
            nav[aria-label="Breadcrumb"] {
                overflow-x: auto;
                white-space: nowrap;
                -webkit-overflow-scrolling: touch;
                scrollbar-width: none;
                -ms-overflow-style: none;
            }

            .breadcrumb::-webkit-scrollbar,
            nav[aria-label="Breadcrumb"]::-webkit-scrollbar {
                display: none;
            }
        }

        /* Bottom sheet style for mobile modals */
        @media (max-width: 640px) {
            .bottom-sheet {
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                max-height: 90vh;
                border-radius: 1.5rem 1.5rem 0 0;
                animation: slideUp 0.3s ease-out;
            }

            @keyframes slideUp {
                from {
                    transform: translateY(100%);
                }
                to {
                    transform: translateY(0);
                }
            }
        }
    `;

    document.head.appendChild(mobileStyles);

    // ================================================
    // TABLE SCROLL DETECTION
    // ================================================

    /**
     *
     */
    function detectTableScroll() {
        document.querySelectorAll('.table-wrapper, .table-responsive').forEach(wrapper => {
            const table = wrapper.querySelector('table');
            if (!table) {
                return;
            }

            if (table.scrollWidth > wrapper.clientWidth) {
                wrapper.classList.add('has-scroll');
            } else {
                wrapper.classList.remove('has-scroll');
            }
        });
    }

    // Wrap standalone tables
    /**
     *
     */
    function wrapTables() {
        document
            .querySelectorAll('table:not(.table-wrapper table):not(.table-responsive table)')
            .forEach(table => {
                if (table.parentElement.classList.contains('table-wrapper')) {
                    return;
                }

                const wrapper = document.createElement('div');
                wrapper.className = 'table-wrapper relative';
                table.parentNode.insertBefore(wrapper, table);
                wrapper.appendChild(table);
            });

        detectTableScroll();
    }

    // ================================================
    // MOBILE MENU ENHANCEMENTS
    // ================================================

    /**
     *
     */
    function enhanceMobileMenu() {
        const mobileMenu = document.getElementById('mobile-menu');
        if (!mobileMenu) {
            return;
        }

        // Add swipe to close
        let touchStartX = 0;
        let touchEndX = 0;

        mobileMenu.addEventListener(
            'touchstart',
            e => {
                touchStartX = e.changedTouches[0].screenX;
            },
            { passive: true }
        );

        mobileMenu.addEventListener(
            'touchend',
            e => {
                touchEndX = e.changedTouches[0].screenX;
                handleSwipe();
            },
            { passive: true }
        );

        /**
         *
         */
        function handleSwipe() {
            const swipeDistance = touchEndX - touchStartX;

            // Swipe right to close (if menu is on left)
            if (swipeDistance > 100) {
                const closeBtn = mobileMenu.querySelector('[onclick*="close"], .close-menu');
                if (closeBtn) {
                    closeBtn.click();
                }
            }
        }
    }

    // ================================================
    // VIEWPORT HEIGHT FIX (for mobile browsers)
    // ================================================

    /**
     *
     */
    function setViewportHeight() {
        // Fix for 100vh on mobile browsers
        const vh = window.innerHeight * 0.01;
        document.documentElement.style.setProperty('--vh', `${vh}px`);
    }

    // Add CSS custom property usage
    const vhFixStyle = document.createElement('style');
    vhFixStyle.textContent = `
        .full-height {
            height: 100vh;
            height: calc(var(--vh, 1vh) * 100);
        }

        .min-full-height {
            min-height: 100vh;
            min-height: calc(var(--vh, 1vh) * 100);
        }
    `;
    document.head.appendChild(vhFixStyle);

    window.addEventListener('resize', setViewportHeight);
    window.addEventListener('orientationchange', () => {
        setTimeout(setViewportHeight, 100);
    });

    // ================================================
    // PULL TO REFRESH INDICATOR
    // ================================================

    let pullStartY = 0;
    let pullMoveY = 0;
    let isPulling = false;

    /**
     *
     */
    function createPullIndicator() {
        if (document.getElementById('pull-indicator')) {
            return;
        }

        const indicator = document.createElement('div');
        indicator.id = 'pull-indicator';
        indicator.innerHTML = `
            <div class="pull-indicator-inner">
                <i class="fas fa-arrow-down"></i>
                <span>Pull to refresh</span>
            </div>
        `;
        indicator.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 0;
            overflow: hidden;
            background: linear-gradient(180deg, #eff6ff, transparent);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: height 0.2s ease;
            z-index: 9998;
        `;

        const inner = indicator.querySelector('.pull-indicator-inner');
        inner.style.cssText = `
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: #3b82f6;
            font-weight: 500;
            opacity: 0;
            transform: translateY(-10px);
            transition: all 0.2s ease;
        `;

        document.body.insertBefore(indicator, document.body.firstChild);
        return indicator;
    }

    // Only on touch devices
    if ('ontouchstart' in window) {
        document.addEventListener(
            'touchstart',
            e => {
                if (window.scrollY === 0) {
                    pullStartY = e.touches[0].clientY;
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

                pullMoveY = e.touches[0].clientY;
                const pullDistance = pullMoveY - pullStartY;

                if (pullDistance > 0 && window.scrollY === 0) {
                    const indicator = createPullIndicator();
                    const height = Math.min(pullDistance * 0.5, 80);
                    indicator.style.height = `${height}px`;

                    const inner = indicator.querySelector('.pull-indicator-inner');
                    inner.style.opacity = Math.min(height / 60, 1);
                    inner.style.transform = `translateY(0) rotate(${Math.min(pullDistance / 2, 180)}deg)`;

                    if (height > 60) {
                        inner.querySelector('span').textContent = 'Release to refresh';
                    } else {
                        inner.querySelector('span').textContent = 'Pull to refresh';
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

                const pullDistance = pullMoveY - pullStartY;
                const indicator = document.getElementById('pull-indicator');

                if (pullDistance > 120 && window.scrollY === 0) {
                    // Trigger refresh
                    if (indicator) {
                        const inner = indicator.querySelector('.pull-indicator-inner');
                        inner.innerHTML =
                            '<i class="fas fa-spinner fa-spin"></i><span>Refreshing...</span>';
                    }

                    setTimeout(() => {
                        window.location.reload();
                    }, 500);
                } else {
                    // Reset
                    if (indicator) {
                        indicator.style.height = '0';
                    }
                }

                isPulling = false;
                pullStartY = 0;
                pullMoveY = 0;
            },
            { passive: true }
        );
    }

    // ================================================
    // INITIALIZATION
    // ================================================

    /**
     *
     */
    function initMobileFixes() {
        setViewportHeight();
        wrapTables();
        enhanceMobileMenu();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initMobileFixes);
    } else {
        initMobileFixes();
    }

    // Re-apply on dynamic content
    const mobileObserver = new MutationObserver(function (mutations) {
        let hasNewTables = false;

        mutations.forEach(mutation => {
            mutation.addedNodes.forEach(node => {
                if (node.nodeType === 1) {
                    if (node.tagName === 'TABLE' || node.querySelector?.('table')) {
                        hasNewTables = true;
                    }
                }
            });
        });

        if (hasNewTables) {
            wrapTables();
        }
    });

    mobileObserver.observe(document.body, { childList: true, subtree: true });

    log('Mobile & Responsive Fixes loaded successfully!');
})();
