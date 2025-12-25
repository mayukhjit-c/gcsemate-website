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

        this._persistence = {
            key: null,
            enabled: false,
            writeTimer: null,
            lastWriteFailed: false,
            throttleMs: 150,
        };
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
        this._persistence.key = key;

        const canUseLocalStorage = () => {
            try {
                const testKey = '__gcsemate_state_test__';
                localStorage.setItem(testKey, '1');
                localStorage.removeItem(testKey);
                return true;
            } catch (_) {
                return false;
            }
        };

        const safeParseJSON = (value) => {
            if (!value || typeof value !== 'string') return null;
            try {
                return JSON.parse(value);
            } catch (_) {
                return null;
            }
        };

        // Load from localStorage on init (best-effort)
        if (canUseLocalStorage()) {
            this._persistence.enabled = true;
            try {
                const saved = localStorage.getItem(key);
                const parsed = safeParseJSON(saved);
                if (parsed && typeof parsed === 'object') {
                    this.state = { ...this.state, ...parsed };
                } else if (saved) {
                    // Corrupt or non-JSON; clear to avoid repeated parse errors.
                    localStorage.removeItem(key);
                }
            } catch (e) {
                console.warn('Failed to load persisted state:', e);
            }
        }

        // Save to localStorage on state change (throttled)
        this.subscribe(() => {
            if (!this._persistence.enabled || this._persistence.lastWriteFailed) {
                return;
            }

            if (this._persistence.writeTimer) {
                clearTimeout(this._persistence.writeTimer);
            }

            this._persistence.writeTimer = setTimeout(() => {
                try {
                    localStorage.setItem(key, JSON.stringify(this.state));
                } catch (e) {
                    // QuotaExceededError or private mode failures: disable for this session.
                    this._persistence.lastWriteFailed = true;
                    console.warn('Failed to persist state (disabled):', e);
                }
            }, this._persistence.throttleMs);
        });
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

