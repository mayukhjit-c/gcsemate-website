// ============================================================================
// SERVER-SIDE PREFERENCES SYSTEM
// Migrates all localStorage to Firebase Firestore
// ============================================================================

/**
 * Server-side preferences manager
 * Replaces all localStorage usage with Firebase
 */
const ServerPreferences = {
    preferences: {},
    unsubscribe: null,
    initialized: false,

    /**
     * Initialize preferences system
     */
    async init() {
        if (!currentUser || !currentUser.uid) {
            // Fallback to localStorage for anonymous users
            this.loadFromLocalStorage();
            return;
        }

        try {
            const db = getFirestore();

            // Load preferences from Firebase
            const prefsDoc = await db.collection('userPreferences').doc(currentUser.uid).get();

            if (prefsDoc.exists) {
                this.preferences = prefsDoc.data();
                this.applyPreferences();
            } else {
                // Migrate from localStorage if available
                await this.migrateFromLocalStorage();
            }

            // Set up real-time listener
            this.setupRealtimeListener();

            this.initialized = true;
        } catch (error) {
            logError(error, 'ServerPreferences.init');
            // Fallback to localStorage on error
            this.loadFromLocalStorage();
        }
    },

    /**
     * Setup real-time listener for preferences
     */
    setupRealtimeListener() {
        if (!currentUser || !currentUser.uid) {
            return;
        }

        try {
            const db = getFirestore();
            this.unsubscribe = db
                .collection('userPreferences')
                .doc(currentUser.uid)
                .onSnapshot(
                    doc => {
                        if (doc.exists) {
                            this.preferences = doc.data();
                            this.applyPreferences();
                        }
                    },
                    error => {
                        logError(error, 'ServerPreferences.setupRealtimeListener');
                    }
                );
        } catch (error) {
            logError(error, 'ServerPreferences.setupRealtimeListener');
        }
    },

    /**
     * Get preference value
     */
    get(key, defaultValue = null) {
        return this.preferences[key] !== undefined ? this.preferences[key] : defaultValue;
    },

    /**
     * Set preference value (async - saves to Firebase)
     */
    async set(key, value) {
        this.preferences[key] = value;

        // Save to localStorage as fallback
        try {
            localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value));
        } catch (error) {
            // Ignore localStorage errors
        }

        // Save to Firebase
        if (!currentUser || !currentUser.uid) {
            return; // Can't save to Firebase without user
        }

        try {
            const db = getFirestore();
            await db
                .collection('userPreferences')
                .doc(currentUser.uid)
                .set(
                    {
                        [key]: value,
                        lastUpdated: firebase.firestore.FieldValue.serverTimestamp(),
                    },
                    { merge: true }
                );
        } catch (error) {
            logError(error, `ServerPreferences.set: ${key}`);
        }
    },

    /**
     * Remove preference
     */
    async remove(key) {
        delete this.preferences[key];

        // Remove from localStorage
        try {
            localStorage.removeItem(key);
        } catch (error) {
            // Ignore
        }

        // Remove from Firebase
        if (!currentUser || !currentUser.uid) {
            return;
        }

        try {
            const db = getFirestore();
            const updateData = {};
            updateData[key] = firebase.firestore.FieldValue.delete();
            updateData.lastUpdated = firebase.firestore.FieldValue.serverTimestamp();

            await db.collection('userPreferences').doc(currentUser.uid).update(updateData);
        } catch (error) {
            logError(error, `ServerPreferences.remove: ${key}`);
        }
    },

    /**
     * Apply all preferences to the UI
     */
    applyPreferences() {
        // Apply theme
        const theme = this.get('theme', 'light');
        if (document.documentElement) {
            document.documentElement.setAttribute('data-theme', theme);
            if (typeof updateThemeIcon === 'function') {
                const themeIcon = document.getElementById('theme-icon');
                const themeIconMobile = document.getElementById('theme-icon-mobile');
                updateThemeIcon(theme, themeIcon, themeIconMobile);
            }
        }

        // Apply accent color
        const accentPalette = this.get('accentPalette');
        if (accentPalette && typeof applyAccent === 'function') {
            applyAccent(accentPalette);
        }

        // Apply footer preference
        const footerHidden = this.get('footerHidden', 'false');
        if (footerHidden === 'true' && typeof toggleFooter === 'function') {
            // Footer is hidden by default if preference is true
        }
    },

    /**
     * Migrate from localStorage to Firebase
     */
    async migrateFromLocalStorage() {
        if (!currentUser || !currentUser.uid) {
            return;
        }

        const migrationMap = {
            theme: 'theme',
            gcsemate_accent: 'accentPalette',
            footerHidden: 'footerHidden',
            notification_welcome_shown: 'notificationWelcomeShown',
            gcsemate_tutorial_shown: 'tutorialShown',
            gcsemate_recent_playlists: 'recentPlaylists',
            dismissedAnnouncement: 'dismissedAnnouncements',
            gcsemate_dismissed_countdowns: 'dismissedCountdowns',
            searchHistory: 'searchHistory',
            savedSearches: 'savedSearches',
        };

        const migrationData = {};
        let hasData = false;

        // Collect all localStorage data
        Object.keys(migrationMap).forEach(localKey => {
            try {
                const value = localStorage.getItem(localKey);
                if (value !== null) {
                    const firebaseKey = migrationMap[localKey];
                    try {
                        migrationData[firebaseKey] = JSON.parse(value);
                    } catch {
                        migrationData[firebaseKey] = value;
                    }
                    hasData = true;
                }
            } catch (error) {
                // Ignore localStorage errors
            }
        });

        if (!hasData) {
            return;
        }

        // Save to Firebase
        try {
            const db = getFirestore();
            migrationData.createdAt = firebase.firestore.FieldValue.serverTimestamp();
            migrationData.lastUpdated = firebase.firestore.FieldValue.serverTimestamp();

            await db
                .collection('userPreferences')
                .doc(currentUser.uid)
                .set(migrationData, { merge: true });
            this.preferences = migrationData;
        } catch (error) {
            logError(error, 'ServerPreferences.migrateFromLocalStorage');
        }
    },

    /**
     * Load from localStorage (fallback for anonymous users)
     */
    loadFromLocalStorage() {
        const keys = [
            'theme',
            'gcsemate_accent',
            'footerHidden',
            'notification_welcome_shown',
            'gcsemate_tutorial_shown',
            'gcsemate_recent_playlists',
            'dismissedAnnouncement',
            'gcsemate_dismissed_countdowns',
            'searchHistory',
            'savedSearches',
        ];

        keys.forEach(key => {
            try {
                const value = localStorage.getItem(key);
                if (value !== null) {
                    try {
                        this.preferences[key] = JSON.parse(value);
                    } catch {
                        this.preferences[key] = value;
                    }
                }
            } catch (error) {
                // Ignore
            }
        });

        this.applyPreferences();
    },

    /**
     * Dispose of listener
     */
    dispose() {
        if (this.unsubscribe) {
            this.unsubscribe();
            this.unsubscribe = null;
        }
        this.initialized = false;
    },
};

// Make globally available
window.ServerPreferences = ServerPreferences;
