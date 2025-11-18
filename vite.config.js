/**
 * Vite configuration for build and development
 * TOOLS IMPROVEMENT #1: BUILD & DEVELOPMENT TOOLS
 */

import { defineConfig } from 'vite';

export default defineConfig({
    root: '.',
    build: {
        outDir: 'dist',
        assetsDir: 'assets',
        sourcemap: true,
        minify: 'terser',
        terserOptions: {
            compress: {
                drop_console: true,
                drop_debugger: true,
            },
        },
        rollupOptions: {
            input: {
                main: './index.html',
            },
            output: {
                manualChunks: {
                    vendor: ['firebase/app', 'firebase/auth', 'firebase/firestore'],
                },
            },
        },
    },
    server: {
        port: 3000,
        open: true,
        cors: true,
    },
    preview: {
        port: 3000,
        open: true,
    },
});

