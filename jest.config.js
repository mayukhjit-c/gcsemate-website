/**
 * Jest configuration for GCSEMate
 * TOOLS IMPROVEMENT #3: TESTING INFRASTRUCTURE
 */

module.exports = {
    testEnvironment: 'jsdom',
    roots: ['<rootDir>'],
    testMatch: ['**/__tests__/**/*.js', '**/?(*.)+(spec|test).js'],
    testPathIgnorePatterns: [
        '<rootDir>/tests/e2e/'
    ],
    collectCoverageFrom: [
        'app.js',
        '**/*.js',
        '!**/node_modules/**',
        '!**/dist/**',
        '!**/build/**',
        '!jest.config.js',
        '!sw.js'
    ],
    // Coverage thresholds disabled for now - will be enabled as tests are added
    // coverageThreshold: {
    //     global: {
    //         branches: 50,
    //         functions: 50,
    //         lines: 50,
    //         statements: 50
    //     }
    // },
    setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
    moduleNameMapper: {
        '\\.(css|less|scss|sass)$': 'identity-obj-proxy'
    },
    testTimeout: 10000
};

