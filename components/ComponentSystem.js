/**
 * Component System for GCSEMate
 * TOOLS IMPROVEMENT #8: CREATE COMPONENT SYSTEM
 *
 * Reusable component functions following a consistent pattern
 */

/**
 * Base component class
 */
class BaseComponent {
    /**
     * @param {HTMLElement} container - Container element
     * @param {Object} props - Component properties
     */
    constructor(container, props = {}) {
        this.container = container;
        this.props = props;
        this.state = {};
    }

    /**
     * Render component
     * @returns {HTMLElement} Rendered element
     */
    render() {
        throw new Error('render() must be implemented');
    }

    /**
     * Update component state
     * @param {Object} newState - New state object
     * @returns {void}
     */
    setState(newState) {
        this.state = { ...this.state, ...newState };
        this.update();
    }

    /**
     * Update component
     * @returns {void}
     */
    update() {
        const newElement = this.render();
        if (this.container && newElement) {
            this.container.replaceWith(newElement);
            this.container = newElement;
        }
    }
}

/**
 * Button component
 * @param {Object} options - Button options
 * @param {string} options.text - Button text
 * @param {string} options.variant - Button variant ('primary' | 'secondary' | 'danger')
 * @param {Function} options.onClick - Click handler
 * @param {string} options.ariaLabel - ARIA label
 * @param {boolean} options.disabled - Disabled state
 * @returns {HTMLElement} Button element
 */
function createButton({ text, variant = 'primary', onClick, ariaLabel, disabled = false }) {
    const button = document.createElement('button');
    button.className = `btn btn-${variant} ${disabled ? 'disabled' : ''}`;
    button.textContent = text;
    button.setAttribute('aria-label', ariaLabel || text);
    button.disabled = disabled;

    if (onClick) {
        button.addEventListener('click', onClick);
    }

    return button;
}

/**
 * Card component
 * @param {Object} options - Card options
 * @param {string} options.title - Card title
 * @param {string} options.content - Card content
 * @param {string} options.icon - Icon class
 * @param {Function} options.onClick - Click handler
 * @returns {HTMLElement} Card element
 */
function createCard({ title, content, icon, onClick }) {
    const card = document.createElement('div');
    card.className = 'card-enhanced card-depth-2';
    card.innerHTML = `
        ${icon ? `<div class="card-icon"><i class="${icon}"></i></div>` : ''}
        <h3 class="card-title">${escapeHTML(title)}</h3>
        <p class="card-content">${escapeHTML(content)}</p>
    `;

    if (onClick) {
        card.addEventListener('click', onClick);
        card.setAttribute('role', 'button');
        card.setAttribute('tabindex', '0');
    }

    return card;
}

/**
 * Input component
 * @param {Object} options - Input options
 * @param {string} options.id - Input ID
 * @param {string} options.type - Input type
 * @param {string} options.label - Label text
 * @param {string} options.placeholder - Placeholder text
 * @param {string} options.value - Input value
 * @param {Function} options.onChange - Change handler
 * @param {string} options.error - Error message
 * @returns {HTMLElement} Input wrapper element
 */
function createInput({ id, type = 'text', label, placeholder, value = '', onChange, error }) {
    const wrapper = document.createElement('div');
    wrapper.className = 'input-wrapper';

    const labelEl = document.createElement('label');
    labelEl.setAttribute('for', id);
    labelEl.textContent = label;
    labelEl.className = 'input-label';

    const input = document.createElement('input');
    input.id = id;
    input.type = type;
    input.placeholder = placeholder;
    input.value = value;
    input.className = `glass-input ${error ? 'input-error' : ''}`;
    input.setAttribute('aria-describedby', error ? `${id}-error` : '');

    if (onChange) {
        input.addEventListener('change', (e) => onChange(e.target.value));
        input.addEventListener('input', (e) => onChange(e.target.value));
    }

    wrapper.appendChild(labelEl);
    wrapper.appendChild(input);

    if (error) {
        const errorEl = document.createElement('div');
        errorEl.id = `${id}-error`;
        errorEl.className = 'input-error-message';
        errorEl.textContent = error;
        errorEl.setAttribute('role', 'alert');
        errorEl.setAttribute('aria-live', 'polite');
        wrapper.appendChild(errorEl);
    }

    return wrapper;
}

/**
 * Modal component
 * @param {Object} options - Modal options
 * @param {string} options.title - Modal title
 * @param {string} options.content - Modal content
 * @param {Array<Object>} options.actions - Action buttons
 * @param {Function} options.onClose - Close handler
 * @returns {HTMLElement} Modal element
 */
function createModal({ title, content, actions = [], onClose }) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'modal-title');

    const modalContent = document.createElement('div');
    modalContent.className = 'modal-content';

    const header = document.createElement('div');
    header.className = 'modal-header';
    header.innerHTML = `
        <h2 id="modal-title">${escapeHTML(title)}</h2>
        <button class="modal-close" aria-label="Close modal" onclick="${onClose ? 'onClose()' : ''}">
            <i class="fas fa-times"></i>
        </button>
    `;

    const body = document.createElement('div');
    body.className = 'modal-body';
    body.innerHTML = content;

    const footer = document.createElement('div');
    footer.className = 'modal-footer';
    actions.forEach(action => {
        const button = createButton(action);
        footer.appendChild(button);
    });

    modalContent.appendChild(header);
    modalContent.appendChild(body);
    modalContent.appendChild(footer);
    modal.appendChild(modalContent);

    return modal;
}

/**
 * Toast component
 * @param {Object} options - Toast options
 * @param {string} options.message - Toast message
 * @param {string} options.type - Toast type ('success' | 'error' | 'warning' | 'info')
 * @param {number} options.duration - Duration in ms
 * @returns {HTMLElement} Toast element
 */
function createToast({ message, type = 'info', duration = 3000 }) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type} toast-enter`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');

    const iconMap = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };

    toast.innerHTML = `
        <i class="fas ${iconMap[type]}"></i>
        <span>${escapeHTML(message)}</span>
        <button class="toast-close" aria-label="Close notification">
            <i class="fas fa-times"></i>
        </button>
    `;

    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', () => {
        toast.classList.add('toast-exit');
        setTimeout(() => toast.remove(), 300);
    });

    if (duration > 0) {
        setTimeout(() => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    return toast;
}

/**
 * Skeleton loader component
 * @param {string} type - Skeleton type ('text' | 'card' | 'avatar')
 * @param {number} count - Number of skeletons
 * @returns {Array<HTMLElement>} Skeleton elements
 */
function createSkeleton(type = 'text', count = 1) {
    const skeletons = [];
    for (let i = 0; i < count; i++) {
        const skeleton = document.createElement('div');
        skeleton.className = `skeleton skeleton-${type}`;
        skeletons.push(skeleton);
    }
    return skeletons;
}

// Export component functions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        BaseComponent,
        createButton,
        createCard,
        createInput,
        createModal,
        createToast,
        createSkeleton
    };
}

