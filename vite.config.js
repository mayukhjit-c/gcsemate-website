/**
 * Vite configuration for build and development
 * TOOLS IMPROVEMENT #1: BUILD & DEVELOPMENT TOOLS
 *
 * Note: This project uses Firebase and other libraries from CDN.
 * For production builds, consider using a simple copy script instead.
 * This config is optimized for development server.
 */

import { defineConfig } from 'vite';

export default defineConfig({
    root: '.',
    publicDir: 'public',
    build: {
        outDir: 'dist',
        assetsDir: 'assets',
        minify: false,
        sourcemap: false,
        // Use a simple HTML plugin that doesn't try to bundle scripts
        rollupOptions: {
            input: './index.html',
        },
        copyPublicDir: true,
        // Increase chunk size warning limit since we're not bundling
        chunkSizeWarningLimit: 1000,
    },
    // Exclude Firebase from dependency optimization
    optimizeDeps: {
        exclude: ['firebase'],
    },
    server: {
        port: 3000,
        open: true,
        cors: true,
        // Properly serve static files
        fs: {
            strict: false,
            allow: ['.'],
        },
    },
    preview: {
        port: 3000,
        open: true,
    },
    // Ensure proper MIME types
    assetsInclude: ['**/*.js', '**/*.css'],
});
