/**
 * State Management System for GCSEMate
 * TOOLS IMPROVEMENT #9: IMPLEMENT STATE MANAGEMENT
 *
 * Simple state management without external libraries
 */

/**
 * State Manager class
 */
class StateManager {
    /**
     * @param {Object} initialState - Initial state
     */
    constructor(initialState = {}) {
        this.state = initialState;
        this.listeners = [];
        this.middleware = [];
    }

    /**
     * Get current state
     * @returns {Object} Current state
     */
    getState() {
        return { ...this.state };
    }

    /**
     * Set state
     * @param {Object|Function} newState - New state or updater function
     * @returns {void}
     */
    setState(newState) {
        const prevState = { ...this.state };

        if (typeof newState === 'function') {
            this.state = { ...this.state, ...newState(this.state) };
        } else {
            this.state = { ...this.state, ...newState };
        }

        // Run middleware
        this.middleware.forEach(middleware => {
            middleware(prevState, this.state);
        });

        // Notify listeners
        this.listeners.forEach(listener => {
            listener(this.state, prevState);
        });
    }

    /**
     * Subscribe to state changes
     * @param {Function} listener - Listener function
     * @returns {Function} Unsubscribe function
     */
    subscribe(listener) {
        this.listeners.push(listener);

        return () => {
            this.listeners = this.listeners.filter(l => l !== listener);
        };
    }

    /**
     * Add middleware
     * @param {Function} middleware - Middleware function
     * @returns {void}
     */
    use(middleware) {
        this.middleware.push(middleware);
    }

    /**
     * Persist state to localStorage
     * @param {string} key - Storage key
     * @returns {void}
     */
    persist(key) {
        // Save to localStorage on every state change
        this.subscribe(() => {
            try {
                localStorage.setItem(key, JSON.stringify(this.state));
            } catch (e) {
                console.warn('Failed to persist state:', e);
            }
        });

        // Load from localStorage on init
        try {
            const saved = localStorage.getItem(key);
            if (saved) {
                this.state = { ...this.state, ...JSON.parse(saved) };
            }
        } catch (e) {
            console.warn('Failed to load persisted state:', e);
        }
    }
}

// Global state manager instance
const appState = new StateManager({
    user: null,
    currentPage: 'subject-dashboard-page',
    theme: 'light',
    notifications: [],
    studySessions: []
});

// Persist user and theme state
appState.persist('appState');

// Export
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { StateManager, appState };
}

