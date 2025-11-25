/**
 * GCSEMate - Visual & UI Fixes
 * Addresses: V-001 to V-007, TR-001 to TR-005
 * Priority: HIGH (🟠)
 */

(function () {
    'use strict';

    console.log('🎨 Loading Visual & UI Fixes...');

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
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', applyVisualFixes);
    } else {
        applyVisualFixes();
    }

    // Re-apply on dynamic content
    const visualObserver = new MutationObserver(function (mutations) {
        mutations.forEach(mutation => {
            if (mutation.addedNodes.length > 0) {
                fixLogoLoading();
            }
        });
    });

    visualObserver.observe(document.body, { childList: true, subtree: true });

    console.log('✅ Visual & UI Fixes loaded successfully!');
})();
