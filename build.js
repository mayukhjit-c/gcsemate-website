/**
 * Simple build script that copies files for production
 * Since this project uses CDN scripts, we just need to copy files
 */

const fs = require('fs');
const path = require('path');

const filesToCopy = [
    'index.html',
    'styles.css',
    'security.js',
    'app-preferences.js',
    'app.js',
    'app-features.js',
    'app-features-enhanced.js',
    'firebase.rules',
];

const dirsToCopy = ['docs', 'functions'];

const distDir = 'dist';

// Create dist directory
if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
}

// Copy files
filesToCopy.forEach(file => {
    if (fs.existsSync(file)) {
        const dest = path.join(distDir, file);
        const destDir = path.dirname(dest);
        if (!fs.existsSync(destDir)) {
            fs.mkdirSync(destDir, { recursive: true });
        }
        fs.copyFileSync(file, dest);
        console.log(`✓ Copied ${file}`);
    } else {
        console.warn(`⚠ File not found: ${file}`);
    }
});

// Copy directories
dirsToCopy.forEach(dir => {
    if (fs.existsSync(dir)) {
        const dest = path.join(distDir, dir);
        copyDir(dir, dest);
        console.log(`✓ Copied directory ${dir}`);
    }
});

/**
 *
 */
function copyDir(src, dest) {
    if (!fs.existsSync(dest)) {
        fs.mkdirSync(dest, { recursive: true });
    }
    const entries = fs.readdirSync(src, { withFileTypes: true });
    for (const entry of entries) {
        const srcPath = path.join(src, entry.name);
        const destPath = path.join(dest, entry.name);
        if (entry.isDirectory()) {
            copyDir(srcPath, destPath);
        } else {
            fs.copyFileSync(srcPath, destPath);
        }
    }
}

console.log('\n✅ Build complete! Files copied to dist/');
