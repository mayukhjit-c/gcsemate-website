/**
 * GCSEMate Code Quality Fixes
 * Addresses issues CQ-001 to CQ-005 from todo.md
 * Priority: Medium
 */

(function () {
    'use strict';

    console.log('🔧 GCSEMate Code Quality Fixes Loading...');

    /**
     * CQ-002: Error Boundary Pattern
     * Wrap async operations in try-catch with proper error handling
     */
    class ErrorBoundary {
        constructor(options = {}) {
            this.name = options.name || 'ErrorBoundary';
            this.onError = options.onError || this.defaultErrorHandler;
            this.retryCount = options.retryCount || 3;
            this.retryDelay = options.retryDelay || 1000;
        }

        defaultErrorHandler(error, context) {
            console.error(`[${this.name}] Error in ${context}:`, error);

            // Report to analytics if available
            if (typeof gtag === 'function') {
                gtag('event', 'exception', {
                    description: `${context}: ${error.message}`,
                    fatal: false,
                });
            }
        }

        // Wrap a synchronous function
        wrap(fn, context = 'unknown') {
            return (...args) => {
                try {
                    return fn(...args);
                } catch (error) {
                    this.onError(error, context);
                    return null;
                }
            };
        }

        // Wrap an async function
        wrapAsync(fn, context = 'unknown') {
            return async (...args) => {
                try {
                    return await fn(...args);
                } catch (error) {
                    this.onError(error, context);
                    return null;
                }
            };
        }

        // Wrap with retry logic
        async withRetry(fn, context = 'unknown') {
            let lastError;

            for (let attempt = 1; attempt <= this.retryCount; attempt++) {
                try {
                    return await fn();
                } catch (error) {
                    lastError = error;
                    console.warn(
                        `[${this.name}] Attempt ${attempt}/${this.retryCount} failed for ${context}`
                    );

                    if (attempt < this.retryCount) {
                        await new Promise(resolve =>
                            setTimeout(resolve, this.retryDelay * attempt)
                        );
                    }
                }
            }

            this.onError(lastError, `${context} (after ${this.retryCount} retries)`);
            throw lastError;
        }
    }

    /**
     * CQ-003: Consistent Naming Conventions
     * Utility to convert between naming conventions
     */
    const NamingConventions = {
        // camelCase to kebab-case
        camelToKebab(str) {
            return str.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
        },

        // kebab-case to camelCase
        kebabToCamel(str) {
            return str.replace(/-([a-z])/g, g => g[1].toUpperCase());
        },

        // camelCase to snake_case
        camelToSnake(str) {
            return str.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
        },

        // snake_case to camelCase
        snakeToCamel(str) {
            return str.replace(/_([a-z])/g, g => g[1].toUpperCase());
        },

        // PascalCase to camelCase
        pascalToCamel(str) {
            return str.charAt(0).toLowerCase() + str.slice(1);
        },

        // camelCase to PascalCase
        camelToPascal(str) {
            return str.charAt(0).toUpperCase() + str.slice(1);
        },
    };

    /**
     * CQ-004: JSDoc Type Checking Helper
     * Runtime type validation for development
     */
    const TypeChecker = {
        isEnabled:
            window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1',

        types: {
            string: val => typeof val === 'string',
            number: val => typeof val === 'number' && !isNaN(val),
            boolean: val => typeof val === 'boolean',
            function: val => typeof val === 'function',
            object: val => val !== null && typeof val === 'object' && !Array.isArray(val),
            array: val => Array.isArray(val),
            null: val => val === null,
            undefined: val => val === undefined,
            any: () => true,
        },

        // Validate a single value
        validate(value, type, name = 'value') {
            if (!this.isEnabled) {
                return true;
            }

            const checker = this.types[type];
            if (!checker) {
                console.warn(`TypeChecker: Unknown type "${type}"`);
                return true;
            }

            if (!checker(value)) {
                console.error(`TypeChecker: ${name} expected ${type}, got ${typeof value}`);
                return false;
            }
            return true;
        },

        // Validate function parameters
        validateParams(params, schema) {
            if (!this.isEnabled) {
                return true;
            }

            let isValid = true;
            for (const [name, type] of Object.entries(schema)) {
                if (!this.validate(params[name], type, name)) {
                    isValid = false;
                }
            }
            return isValid;
        },

        // Create a type-checked function wrapper
        typed(fn, paramSchema, returnType) {
            if (!this.isEnabled) {
                return fn;
            }

            return (...args) => {
                // Validate parameters
                const paramNames = Object.keys(paramSchema);
                paramNames.forEach((name, i) => {
                    this.validate(args[i], paramSchema[name], name);
                });

                const result = fn(...args);

                // Validate return type
                if (returnType) {
                    this.validate(result, returnType, 'return value');
                }

                return result;
            };
        },
    };

    /**
     * CQ-005: Code Organization - Module Registry
     * Helps manage and organize code modules
     */
    class ModuleRegistry {
        constructor() {
            this.modules = new Map();
            this.dependencies = new Map();
            this.initialized = new Set();
        }

        // Register a module
        register(name, module, dependencies = []) {
            if (this.modules.has(name)) {
                console.warn(`Module "${name}" already registered`);
                return;
            }

            this.modules.set(name, module);
            this.dependencies.set(name, dependencies);

            console.log(`📦 Module registered: ${name}`);
        }

        // Get a module
        get(name) {
            return this.modules.get(name);
        }

        // Initialize a module and its dependencies
        async init(name) {
            if (this.initialized.has(name)) {
                return this.modules.get(name);
            }

            const module = this.modules.get(name);
            if (!module) {
                throw new Error(`Module "${name}" not found`);
            }

            // Initialize dependencies first
            const deps = this.dependencies.get(name) || [];
            for (const dep of deps) {
                await this.init(dep);
            }

            // Initialize module
            if (typeof module.init === 'function') {
                await module.init();
            }

            this.initialized.add(name);
            console.log(`✅ Module initialized: ${name}`);

            return module;
        }

        // Initialize all modules
        async initAll() {
            for (const name of this.modules.keys()) {
                await this.init(name);
            }
        }

        // List all modules
        list() {
            return Array.from(this.modules.keys());
        }
    }

    /**
     * Event Emitter Pattern for Loose Coupling
     */
    class EventEmitter {
        constructor() {
            this.events = new Map();
        }

        // Subscribe to an event
        on(event, callback) {
            if (!this.events.has(event)) {
                this.events.set(event, new Set());
            }
            this.events.get(event).add(callback);

            // Return unsubscribe function
            return () => this.off(event, callback);
        }

        // Subscribe once
        once(event, callback) {
            const wrapper = (...args) => {
                this.off(event, wrapper);
                callback(...args);
            };
            return this.on(event, wrapper);
        }

        // Unsubscribe from an event
        off(event, callback) {
            const callbacks = this.events.get(event);
            if (callbacks) {
                callbacks.delete(callback);
            }
        }

        // Emit an event
        emit(event, ...args) {
            const callbacks = this.events.get(event);
            if (callbacks) {
                callbacks.forEach(callback => {
                    try {
                        callback(...args);
                    } catch (error) {
                        console.error(`Error in event handler for "${event}":`, error);
                    }
                });
            }
        }

        // Remove all listeners for an event
        removeAllListeners(event) {
            if (event) {
                this.events.delete(event);
            } else {
                this.events.clear();
            }
        }
    }

    /**
     * Observable State Pattern
     * For reactive state management
     */
    class ObservableState {
        constructor(initialState = {}) {
            this.state = initialState;
            this.listeners = new Set();
            this.computed = new Map();
        }

        // Get current state
        getState() {
            return { ...this.state };
        }

        // Update state
        setState(updates) {
            const prevState = this.state;
            this.state = { ...this.state, ...updates };

            // Notify listeners
            this.listeners.forEach(listener => {
                try {
                    listener(this.state, prevState);
                } catch (error) {
                    console.error('Error in state listener:', error);
                }
            });
        }

        // Subscribe to state changes
        subscribe(listener) {
            this.listeners.add(listener);
            return () => this.listeners.delete(listener);
        }

        // Add computed property
        addComputed(name, computeFn) {
            this.computed.set(name, computeFn);
        }

        // Get computed value
        getComputed(name) {
            const computeFn = this.computed.get(name);
            if (computeFn) {
                return computeFn(this.state);
            }
            return undefined;
        }
    }

    /**
     * Logger with Levels
     */
    class Logger {
        static LEVELS = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3,
            NONE: 4,
        };

        constructor(options = {}) {
            this.name = options.name || 'App';
            this.level =
                options.level !== undefined
                    ? options.level
                    : window.location.hostname === 'localhost'
                      ? Logger.LEVELS.DEBUG
                      : Logger.LEVELS.WARN;
            this.history = [];
            this.maxHistory = options.maxHistory || 100;
        }

        formatMessage(level, ...args) {
            const timestamp = new Date().toISOString();
            const prefix = `[${timestamp}] [${this.name}] [${level}]`;
            return { prefix, args };
        }

        log(level, levelName, ...args) {
            if (level < this.level) {
                return;
            }

            const { prefix, args: msgArgs } = this.formatMessage(levelName, ...args);

            // Store in history
            this.history.push({ timestamp: Date.now(), level: levelName, message: msgArgs });
            if (this.history.length > this.maxHistory) {
                this.history.shift();
            }

            // Output
            switch (level) {
                case Logger.LEVELS.DEBUG:
                    console.debug(prefix, ...msgArgs);
                    break;
                case Logger.LEVELS.INFO:
                    console.info(prefix, ...msgArgs);
                    break;
                case Logger.LEVELS.WARN:
                    console.warn(prefix, ...msgArgs);
                    break;
                case Logger.LEVELS.ERROR:
                    console.error(prefix, ...msgArgs);
                    break;
            }
        }

        debug(...args) {
            this.log(Logger.LEVELS.DEBUG, 'DEBUG', ...args);
        }
        info(...args) {
            this.log(Logger.LEVELS.INFO, 'INFO', ...args);
        }
        warn(...args) {
            this.log(Logger.LEVELS.WARN, 'WARN', ...args);
        }
        error(...args) {
            this.log(Logger.LEVELS.ERROR, 'ERROR', ...args);
        }

        getHistory() {
            return [...this.history];
        }
        clearHistory() {
            this.history = [];
        }
    }

    /**
     * Dependency Injection Container
     */
    class DIContainer {
        constructor() {
            this.services = new Map();
            this.singletons = new Map();
        }

        // Register a service
        register(name, factory, singleton = true) {
            this.services.set(name, { factory, singleton });
        }

        // Resolve a service
        resolve(name) {
            const service = this.services.get(name);
            if (!service) {
                throw new Error(`Service "${name}" not registered`);
            }

            if (service.singleton) {
                if (!this.singletons.has(name)) {
                    this.singletons.set(name, service.factory(this));
                }
                return this.singletons.get(name);
            }

            return service.factory(this);
        }

        // Check if service exists
        has(name) {
            return this.services.has(name);
        }
    }

    // Create global instances
    const moduleRegistry = new ModuleRegistry();
    const eventBus = new EventEmitter();
    const appState = new ObservableState({
        user: null,
        theme: 'light',
        isLoading: false,
        errors: [],
    });
    const logger = new Logger({ name: 'GCSEMate' });
    const container = new DIContainer();
    const errorBoundary = new ErrorBoundary({ name: 'GCSEMate' });

    // Register core services
    container.register('logger', () => logger);
    container.register('eventBus', () => eventBus);
    container.register('state', () => appState);
    container.register('moduleRegistry', () => moduleRegistry);

    // Export for use by other modules
    window.GCSEMateCodeQuality = {
        ErrorBoundary,
        NamingConventions,
        TypeChecker,
        ModuleRegistry,
        EventEmitter,
        ObservableState,
        Logger,
        DIContainer,
        // Global instances
        moduleRegistry,
        eventBus,
        appState,
        logger,
        container,
        errorBoundary,
    };

    // Initialize
    /**
     *
     */
    function init() {
        // Add computed properties
        appState.addComputed('isAuthenticated', state => state.user !== null);
        appState.addComputed('hasErrors', state => state.errors.length > 0);

        // Log state changes in development
        if (TypeChecker.isEnabled) {
            appState.subscribe((newState, prevState) => {
                logger.debug('State changed:', { from: prevState, to: newState });
            });
        }

        console.log('✅ GCSEMate Code Quality Fixes Applied');
    }

    // Run on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
