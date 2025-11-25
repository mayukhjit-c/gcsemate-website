/**
 * GCSEMate - Animation Fixes
 * Addresses: AN-001 to AN-004, Performance optimizations
 * Priority: HIGH (🟠)
 */

(function () {
    'use strict';

    // Debug logging - silent in production
    const DEBUG = false;
    const log = DEBUG
        ? Function.prototype.bind.call(console.log, console, '🎬 [Animation]') // eslint-disable-line no-console
        : () => {};

    log('Loading Animation Fixes...');

    const animationStyles = document.createElement('style');
    animationStyles.id = 'animation-fixes';
    animationStyles.textContent = `
        /* ================================================ */
        /* AN-001: RESPECT prefers-reduced-motion */
        /* ================================================ */

        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }

            /* Disable specific animations */
            .animate-hero-title,
            .animate-hero-subtitle,
            .animate-hero-buttons,
            .animate-feature-card,
            .animate-fade-in,
            .animate-slide-in,
            .animate-slide-up,
            [class*="animate-"] {
                animation: none !important;
                opacity: 1 !important;
                transform: none !important;
            }

            /* Keep loaders visible but static */
            .loader,
            .spinner,
            [class*="spin"] {
                animation: none !important;
            }

            /* Disable hover transforms */
            .card-modern:hover,
            .modern-card:hover,
            button:hover,
            a:hover {
                transform: none !important;
            }

            /* Disable parallax */
            .parallax {
                transform: none !important;
            }
        }

        /* ================================================ */
        /* AN-002: OPTIMIZED HERO ANIMATIONS */
        /* ================================================ */

        /* Faster hero animations */
        .animate-hero-title {
            animation: heroFadeIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            animation-delay: 0.05s;
            opacity: 0;
        }

        .animate-hero-subtitle {
            animation: heroFadeIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            animation-delay: 0.15s;
            opacity: 0;
        }

        .animate-hero-buttons {
            animation: heroFadeIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            animation-delay: 0.25s;
            opacity: 0;
        }

        @keyframes heroFadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Feature card staggered animation */
        .animate-feature-card {
            animation: cardFadeIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
            opacity: 0;
        }

        @keyframes cardFadeIn {
            from {
                opacity: 0;
                transform: translateY(15px) scale(0.98);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        /* ================================================ */
        /* AN-003: CENTERED LOADING SPINNER */
        /* ================================================ */

        #app-loading {
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            min-height: 100vh !important;
            min-height: calc(var(--vh, 1vh) * 100) !important;
        }

        #app-loading > div {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        /* Loading bar animation */
        .loading-bar {
            width: 200px;
            max-width: 80vw;
            height: 4px;
            background: #e5e7eb;
            border-radius: 2px;
            overflow: hidden;
            margin-top: 1rem;
        }

        .loading-bar-progress {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--primary-light), var(--primary));
            background-size: 200% 100%;
            animation: loadingProgress 1.5s ease-in-out infinite;
            border-radius: 2px;
        }

        @keyframes loadingProgress {
            0% {
                width: 20%;
                background-position: 100% 0;
            }
            50% {
                width: 60%;
                background-position: 0% 0;
            }
            100% {
                width: 20%;
                background-position: 100% 0;
            }
        }

        /* ================================================ */
        /* AN-004: STAR ICON ANIMATION FIX */
        /* ================================================ */

        .star-icon {
            transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1),
                        color 0.2s ease;
            display: inline-flex;
            will-change: transform;
        }

        .star-icon:hover {
            transform: scale(1.15);
        }

        .star-icon.starred {
            color: #fbbf24 !important;
            transform: scale(1.1);
        }

        .star-icon.starred:hover {
            transform: scale(1.2);
        }

        /* Star click animation */
        .star-icon.animating {
            animation: starPop 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        @keyframes starPop {
            0% { transform: scale(1); }
            50% { transform: scale(1.3); }
            100% { transform: scale(1.1); }
        }

        /* ================================================ */
        /* PERFORMANCE OPTIMIZATIONS */
        /* ================================================ */

        /* GPU acceleration for animated elements */
        .card-modern,
        .modern-card,
        .glass-card-premium,
        button,
        .btn,
        .modal-content,
        [class*="animate-"] {
            transform: translateZ(0);
            backface-visibility: hidden;
            perspective: 1000px;
        }

        /* Use will-change sparingly */
        .card-modern:hover,
        .modern-card:hover {
            will-change: transform, box-shadow;
        }

        /* Remove will-change after animation */
        .card-modern:not(:hover),
        .modern-card:not(:hover) {
            will-change: auto;
        }

        /* ================================================ */
        /* SMOOTH PAGE TRANSITIONS */
        /* ================================================ */

        .page-enter {
            opacity: 0;
            transform: translateY(10px);
        }

        .page-enter-active {
            opacity: 1;
            transform: translateY(0);
            transition: opacity 0.3s ease, transform 0.3s ease;
        }

        .page-exit {
            opacity: 1;
            transform: translateY(0);
        }

        .page-exit-active {
            opacity: 0;
            transform: translateY(-10px);
            transition: opacity 0.2s ease, transform 0.2s ease;
        }

        /* ================================================ */
        /* SKELETON LOADING STATES */
        /* ================================================ */

        .skeleton {
            background: linear-gradient(
                90deg,
                #f0f0f0 25%,
                #e0e0e0 50%,
                #f0f0f0 75%
            );
            background-size: 200% 100%;
            animation: skeletonShimmer 1.5s infinite;
            border-radius: 4px;
        }

        .skeleton-text {
            height: 1em;
            margin-bottom: 0.5em;
        }

        .skeleton-text:last-child {
            width: 70%;
        }

        .skeleton-avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
        }

        .skeleton-card {
            height: 150px;
            border-radius: 12px;
        }

        @keyframes skeletonShimmer {
            0% { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }

        /* ================================================ */
        /* MICRO-INTERACTIONS */
        /* ================================================ */

        /* Button press effect */
        button:active:not(:disabled),
        .btn:active:not(:disabled) {
            transform: scale(0.97) translateZ(0);
            transition: transform 0.1s ease;
        }

        /* Checkbox/toggle animations */
        input[type="checkbox"] {
            transition: all 0.2s ease;
        }

        input[type="checkbox"]:checked {
            animation: checkboxPop 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
        }

        @keyframes checkboxPop {
            0% { transform: scale(1); }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); }
        }

        /* Input focus animation */
        input:focus,
        textarea:focus,
        select:focus {
            animation: inputFocus 0.2s ease;
        }

        @keyframes inputFocus {
            0% { box-shadow: 0 0 0 0 rgba(99, 102, 241, 0.4); }
            100% { box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.15); }
        }

        /* ================================================ */
        /* TOAST ANIMATIONS */
        /* ================================================ */

        .toast-enter {
            animation: toastSlideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }

        .toast-exit {
            animation: toastSlideOut 0.2s ease-in forwards;
        }

        @keyframes toastSlideIn {
            from {
                opacity: 0;
                transform: translateX(100%) scale(0.9);
            }
            to {
                opacity: 1;
                transform: translateX(0) scale(1);
            }
        }

        @keyframes toastSlideOut {
            from {
                opacity: 1;
                transform: translateX(0) scale(1);
            }
            to {
                opacity: 0;
                transform: translateX(100%) scale(0.9);
            }
        }

        /* ================================================ */
        /* RIPPLE EFFECT */
        /* ================================================ */

        .ripple-container {
            position: relative;
            overflow: hidden;
        }

        .ripple {
            position: absolute;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.5);
            transform: scale(0);
            animation: rippleExpand 0.6s ease-out;
            pointer-events: none;
        }

        @keyframes rippleExpand {
            to {
                transform: scale(2.5);
                opacity: 0;
            }
        }

        /* ================================================ */
        /* PROGRESS BAR */
        /* ================================================ */

        .progress-bar {
            height: 4px;
            background: #e5e7eb;
            border-radius: 2px;
            overflow: hidden;
        }

        .progress-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--primary-light));
            border-radius: 2px;
            transition: width 0.3s ease;
        }

        .progress-bar-indeterminate .progress-bar-fill {
            width: 30%;
            animation: progressIndeterminate 1.5s ease-in-out infinite;
        }

        @keyframes progressIndeterminate {
            0% { transform: translateX(-100%); }
            50% { transform: translateX(200%); }
            100% { transform: translateX(-100%); }
        }
    `;

    document.head.appendChild(animationStyles);

    // ================================================
    // HELPER FUNCTIONS
    // ================================================

    // Create skeleton loading placeholder
    window.createSkeleton = function (type = 'text', count = 3) {
        if (type === 'card') {
            return '<div class="skeleton skeleton-card"></div>';
        }

        if (type === 'avatar-text') {
            return `
                <div class="flex items-center gap-3">
                    <div class="skeleton skeleton-avatar"></div>
                    <div class="flex-1">
                        <div class="skeleton skeleton-text w-1/2"></div>
                        <div class="skeleton skeleton-text w-3/4"></div>
                    </div>
                </div>
            `;
        }

        let html = '';
        for (let i = 0; i < count; i++) {
            const width = i === count - 1 ? '70%' : '100%';
            html += `<div class="skeleton skeleton-text" style="width: ${width}"></div>`;
        }
        return html;
    };

    // Add ripple effect to element
    window.addRipple = function (element, event) {
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;

        const ripple = document.createElement('span');
        ripple.className = 'ripple';
        ripple.style.cssText = `
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
        `;

        element.classList.add('ripple-container');
        element.appendChild(ripple);

        ripple.addEventListener('animationend', () => ripple.remove());
    };

    // Animate element on scroll into view
    const animateOnScroll = new IntersectionObserver(
        entries => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-visible');
                    animateOnScroll.unobserve(entry.target);
                }
            });
        },
        { threshold: 0.1 }
    );

    window.animateOnScroll = function (element) {
        element.classList.add('animate-on-scroll');
        animateOnScroll.observe(element);
    };

    // Add CSS for scroll animations
    const scrollAnimStyles = document.createElement('style');
    scrollAnimStyles.textContent = `
        .animate-on-scroll {
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.5s ease, transform 0.5s ease;
        }

        .animate-on-scroll.animate-visible {
            opacity: 1;
            transform: translateY(0);
        }
    `;
    document.head.appendChild(scrollAnimStyles);

    // Initialize scroll animations for existing elements
    /**
     *
     */
    function initScrollAnimations() {
        document.querySelectorAll('[data-animate-on-scroll]').forEach(el => {
            window.animateOnScroll(el);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initScrollAnimations);
    } else {
        initScrollAnimations();
    }

    log('Animation Fixes loaded successfully!');
})();
