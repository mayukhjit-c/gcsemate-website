/**
 * GCSEMate - Comprehensive Bug Fixes & Improvements
 * Addresses modal blank display, color contrast, and interaction issues
 */

(function () {
    'use strict';

    console.log('🔧 Loading comprehensive bug fixes...');

    // ==========================================
    // FIX 1: Modal Content Pre-loading System
    // ==========================================
    // Ensures modal content is fully loaded before display

    const modalQueue = new Map();

    window.enhancedShowModal = function (modalId, contentLoader) {
        const modal = document.getElementById(modalId);
        if (!modal) {
            console.warn(`Modal ${modalId} not found`);
            return;
        }

        // Prevent double-opening
        if (modalQueue.has(modalId)) {
            return;
        }

        modalQueue.set(modalId, true);

        // Load content first
        if (contentLoader && typeof contentLoader === 'function') {
            try {
                contentLoader(modal);
            } catch (error) {
                console.error('Error loading modal content:', error);
            }
        }

        // Wait for next frame to ensure content is rendered
        requestAnimationFrame(() => {
            // Ensure modal is visible but transparent
            modal.classList.remove('hidden');
            modal.style.display = 'flex';
            modal.style.opacity = '0';
            modal.style.transform = 'scale(0.95)';

            // Trigger animation after content is ready
            requestAnimationFrame(() => {
                modal.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
                modal.style.opacity = '1';
                modal.style.transform = 'scale(1)';

                // Add modal-open class to body
                document.body.classList.add('modal-open');

                // Remove from queue after animation
                setTimeout(() => {
                    modalQueue.delete(modalId);
                }, 300);
            });
        });
    };

    // ==========================================
    // FIX 2: Enhanced Modal Close with Cleanup
    // ==========================================

    window.enhancedCloseModal = function (modalId) {
        const modal = document.getElementById(modalId);
        if (!modal) {
            return;
        }

        // Animate out
        modal.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
        modal.style.opacity = '0';
        modal.style.transform = 'scale(0.95)';

        setTimeout(() => {
            modal.classList.add('hidden');
            modal.style.display = 'none';
            modal.style.opacity = '';
            modal.style.transform = '';
            modal.style.transition = '';

            // Remove modal-open class if no more modals
            const visibleModals = document.querySelectorAll('.fixed:not(.hidden)');
            if (visibleModals.length === 0) {
                document.body.classList.remove('modal-open');
            }

            // Clean up if needed
            if (modal.dataset.clearOnClose === 'true') {
                modal.innerHTML = '';
            }
        }, 200);
    };

    // ==========================================
    // FIX 3: Fix Existing Modal Functions
    // ==========================================
    // Wrap existing modal functions to prevent blank displays

    const originalShowModal = window.showModal;
    if (originalShowModal) {
        window.showModal = function (...args) {
            // Add small delay to ensure content renders
            setTimeout(() => originalShowModal.apply(this, args), 10);
        };
    }

    // ==========================================
    // FIX 4: Auto-fix Cards on Load
    // ==========================================
    // Ensure all cards have proper contrast and animations

    /**
     *
     */
    function fixCardStyling() {
        const cards = document.querySelectorAll('.card-modern, .modern-card, .glass-card-premium');

        cards.forEach((card, index) => {
            // Add entrance animation
            card.classList.add('card-entrance');
            card.style.animationDelay = `${index * 0.05}s`;

            // Ensure proper text contrast
            const textElements = card.querySelectorAll('p, span, div:not([class*="bg-"])');
            textElements.forEach(el => {
                const bgColor = window.getComputedStyle(card).backgroundColor;
                if (isLightBackground(bgColor)) {
                    el.style.color = '#0f172a'; // Dark text
                } else {
                    el.style.color = '#ffffff'; // White text
                }
            });
        });
    }

    // Helper to detect light backgrounds
    /**
     *
     */
    function isLightBackground(colorString) {
        const rgb = colorString.match(/\d+/g);
        if (!rgb || rgb.length < 3) {
            return true;
        }
        const brightness =
            (parseInt(rgb[0]) * 299 + parseInt(rgb[1]) * 587 + parseInt(rgb[2]) * 114) / 1000;
        return brightness > 150;
    }

    // ==========================================
    // FIX 5: Button Click Feedback
    // ==========================================
    // Add ripple effect to all buttons

    /**
     *
     */
    function addButtonRipple() {
        const buttons = document.querySelectorAll('button, .btn');

        buttons.forEach(button => {
            if (button.classList.contains('ripple-initialized')) {
                return;
            }

            button.classList.add('ripple-initialized', 'btn-ripple');

            button.addEventListener('click', function (e) {
                const ripple = document.createElement('span');
                const rect = this.getBoundingClientRect();
                const size = Math.max(rect.width, rect.height);
                const x = e.clientX - rect.left - size / 2;
                const y = e.clientY - rect.top - size / 2;

                ripple.style.cssText = `
                    position: absolute;
                    width: ${size}px;
                    height: ${size}px;
                    left: ${x}px;
                    top: ${y}px;
                    border-radius: 50%;
                    background: rgba(255, 255, 255, 0.5);
                    pointer-events: none;
                    animation: ripple-expand 0.6s ease-out;
                `;

                this.style.position = 'relative';
                this.style.overflow = 'hidden';
                this.appendChild(ripple);

                setTimeout(() => ripple.remove(), 600);
            });
        });
    }

    // Add ripple animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes ripple-expand {
            from {
                transform: scale(0);
                opacity: 0.8;
            }
            to {
                transform: scale(2);
                opacity: 0;
            }
        }

        /* Prevent body scroll when modal open */
        body.modal-open {
            overflow: hidden;
        }

        /* Ensure modals are above everything */
        .fixed[role="dialog"],
        .fixed.modal {
            z-index: 9999;
        }

        /* Smooth transitions for all interactive elements */
        button, .btn, a, input, select, textarea {
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }
    `;
    document.head.appendChild(style);

    // ==========================================
    // FIX 6: Auto-apply Fixes on DOM Changes
    // ==========================================

    const observer = new MutationObserver(mutations => {
        let shouldFix = false;

        mutations.forEach(mutation => {
            if (mutation.addedNodes.length > 0) {
                shouldFix = true;
            }
        });

        if (shouldFix) {
            setTimeout(() => {
                fixCardStyling();
                addButtonRipple();
            }, 100);
        }
    });

    // ==========================================
    // FIX 7: Initialize on Load
    // ==========================================

    /**
     *
     */
    function initializeFixes() {
        console.log('✅ Applying bug fixes...');

        // Fix existing elements
        fixCardStyling();
        addButtonRipple();

        // Start observing
        observer.observe(document.body, {
            childList: true,
            subtree: true,
        });

        // Fix any modals that might be open
        const openModals = document.querySelectorAll('.fixed:not(.hidden)');
        openModals.forEach(modal => {
            if (modal.id) {
                // Ensure they have proper opacity
                if (modal.style.opacity === '0' || !modal.style.opacity) {
                    modal.style.opacity = '1';
                }
            }
        });

        console.log('✅ All bug fixes applied successfully!');
    }

    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeFixes);
    } else {
        initializeFixes();
    }

    // Also run after a short delay to catch any dynamically loaded content
    setTimeout(initializeFixes, 1000);

    // ==========================================
    // FIX 8: Keyboard Navigation Improvements
    // ==========================================

    document.addEventListener('keydown', e => {
        // ESC to close modals (already handled but ensuring it works)
        if (e.key === 'Escape') {
            const openModals = Array.from(document.querySelectorAll('.fixed:not(.hidden)'));
            const topModal = openModals[openModals.length - 1];
            if (topModal && topModal.id) {
                if (typeof window.closeModal === 'function') {
                    window.closeModal(topModal.id);
                } else if (typeof window.enhancedCloseModal === 'function') {
                    window.enhancedCloseModal(topModal.id);
                }
            }
        }

        // Tab trap for modals
        if (e.key === 'Tab') {
            const openModal = document.querySelector('.fixed:not(.hidden)');
            if (openModal) {
                const focusableElements = openModal.querySelectorAll(
                    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
                );
                const firstFocusable = focusableElements[0];
                const lastFocusable = focusableElements[focusableElements.length - 1];

                if (e.shiftKey && document.activeElement === firstFocusable) {
                    lastFocusable.focus();
                    e.preventDefault();
                } else if (!e.shiftKey && document.activeElement === lastFocusable) {
                    firstFocusable.focus();
                    e.preventDefault();
                }
            }
        }
    });

    console.log('🎉 GCSEMate bug fixes loaded successfully!');
})();
