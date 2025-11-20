// GCSEMate Modal Improvements
// Universal modal close handler with escape key support and smooth animations

(function () {
    'use strict';

    // Universal modal close function with smooth fade out
    window.closeModal = function (modalId) {
        const modal = document.getElementById(modalId);
        if (!modal) {
            return;
        }

        // Add fade out animation
        modal.style.opacity = '0';
        modal.style.transform = 'scale(0.95)';

        setTimeout(() => {
            modal.style.display = 'none';
            modal.style.opacity = '';
            modal.style.transform = '';

            // Clean up modal content if specified
            if (modal.dataset.clearOnClose === 'true') {
                modal.innerHTML = '';
            }
        }, 250);
    };

    // Enhanced modal close with element removal
    window.closeAndRemoveModal = function (element) {
        const modal = element.closest('.fixed') || element.closest('[role="dialog"]');
        if (!modal) {
            return;
        }

        modal.style.opacity = '0';
        modal.style.transform = 'scale(0.95)';

        setTimeout(() => {
            modal.remove();
        }, 250);
    };

    // Global escape key handler for all modals
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' || e.keyCode === 27) {
            // Find all visible modals
            const modals = document.querySelectorAll(
                '.fixed[style*="display: block"], .fixed:not([style*="display: none"])'
            );

            // Close the topmost modal
            if (modals.length > 0) {
                const topModal = modals[modals.length - 1];
                const modalId = topModal.id;

                if (modalId) {
                    closeModal(modalId);
                } else {
                    closeAndRemoveModal(topModal);
                }
            }
        }
    });

    // Click outside to close modals
    document.addEventListener('click', function (e) {
        if (
            e.target.classList.contains('modal-backdrop') ||
            (e.target.classList.contains('fixed') && e.target.classList.contains('inset-0'))
        ) {
            closeAndRemoveModal(e.target);
        }
    });

    // Add smooth transition to all modals
    const style = document.createElement('style');
    style.textContent = `
        .fixed[role="dialog"],
        .modal-container {
            transition: opacity 0.25s cubic-bezier(0.4, 0, 0.2, 1),
                        transform 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        }

        /* Prevent body scroll when modal is open */
        body.modal-open {
            overflow: hidden;
        }

        /* Smooth backdrop */
        .modal-backdrop {
            backdrop-filter: blur(8px);
            transition: backdrop-filter 0.3s ease;
        }
    `;
    document.head.appendChild(style);

    // Helper: Mark body when modal opens
    window.addEventListener('DOMNodeInserted', function (e) {
        if (
            e.target.classList &&
            e.target.classList.contains('fixed') &&
            e.target.style.display !== 'none'
        ) {
            document.body.classList.add('modal-open');
        }
    });

    // Helper: Unmark body when modal closes
    const observer = new MutationObserver(function (mutations) {
        const hasVisibleModal = document.querySelector(
            '.fixed[style*="display: block"], .fixed:not([style*="display: none"])'
        );
        if (!hasVisibleModal) {
            document.body.classList.remove('modal-open');
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['style'],
    });

    console.log('✅ Modal improvements loaded - Escape key & click outside support enabled');
})();
