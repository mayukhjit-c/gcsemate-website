#!/usr/bin/env node
/**
 * GCSEMate production build
 * -------------------------------------------------------------
 * - Mirrors the whole project into dist/ (nothing gets missed:
 *   images, assets/, functions/, subpages, rules, etc.)
 * - Minifies JS + CSS with esbuild, HTML with html-minifier-terser
 * - Drops console.* / debugger from the app bundle (keeps banners
 *   in security.js and logging in sw.js)
 * - Appends a content-hash ?v= cache-buster to local asset refs in
 *   HTML so deploys are picked up instantly without breaking caches
 * - Bumps the service-worker cache name to the new build hash
 *
 * Requires dev deps (installed via `npm install`):
 *   esbuild, html-minifier-terser
 * Run with: npm run build
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const esbuild = require('esbuild');
const { minify: minifyHtml } = require('html-minifier-terser');

const ROOT = __dirname;
const DIST = path.join(ROOT, 'dist');

// Never deploy these (dev tooling, source notes, build artifacts).
const DENY = new Set([
	'node_modules', 'dist', '.git', '.github', 'src', '.vscode',
	'build.js', 'vite.config.js', 'tailwind.config.js', 'postcss.config.js',
	'package.json', 'package-lock.json', 'jest.config.js', 'jest.setup.js',
	'playwright.config.js', '.eslintrc.json', '.prettierrc.json',
	'.prettierignore', '.gitignore', 'tests', '__tests__', 'e2e',
	'README.md', 'todo.md', 'BUILD_INSTRUCTIONS.md', 'FIXES_DOCUMENTATION.md',
	'IMPROVEMENTS_APPLIED.md', 'IMPROVEMENTS_SUGGESTIONS.md',
]);

// JS files that must keep console output (copyright banner / SW diagnostics).
const KEEP_CONSOLE = new Set(['security.js', 'sw.js']);

// Top-level local asset refs in HTML that get a ?v=<hash> cache-buster.
const BUSTABLE = ['app.js', 'styles.css', 'tailwind.css', 'security.js'];

const hash8 = (buf) => crypto.createHash('sha256').update(buf).digest('hex').slice(0, 8);
const ensureDir = (p) => fs.mkdirSync(p, { recursive: true });
const rimraf = (p) => fs.existsSync(p) && fs.rmSync(p, { recursive: true, force: true });

function walk(dir, out = []) {
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		if (DENY.has(entry.name)) continue;
		const abs = path.join(dir, entry.name);
		if (entry.isDirectory()) walk(abs, out);
		else out.push(abs);
	}
	return out;
}

async function run() {
	const t0 = Date.now();
	console.log('\u{1F9F9} Cleaning dist/');
	rimraf(DIST);
	ensureDir(DIST);

	const files = walk(ROOT);
	const hashes = {}; // rel path (posix) -> 8-char content hash
	let js = 0, css = 0, html = 0, copied = 0;

	// Pass 1: copy everything; minify JS + CSS in place.
	for (const abs of files) {
		const rel = path.relative(ROOT, abs);
		const relPosix = rel.split(path.sep).join('/');
		const dest = path.join(DIST, rel);
		const ext = path.extname(abs).toLowerCase();
		const base = path.basename(abs);
		ensureDir(path.dirname(dest));

		if (ext === '.js') {
			const code = fs.readFileSync(abs, 'utf8');
			const out = await esbuild.transform(code, {
				loader: 'js',
				minify: true,
				legalComments: 'none',
				drop: KEEP_CONSOLE.has(base) ? [] : ['console', 'debugger'],
			});
			fs.writeFileSync(dest, out.code);
			hashes[relPosix] = hash8(out.code);
			js++;
		} else if (ext === '.css') {
			const code = fs.readFileSync(abs, 'utf8');
			const out = await esbuild.transform(code, { loader: 'css', minify: true });
			fs.writeFileSync(dest, out.code);
			hashes[relPosix] = hash8(out.code);
			css++;
		} else {
			fs.copyFileSync(abs, dest); // HTML handled in pass 2; binaries copied verbatim
			if (ext !== '.html') copied++;
		}
	}

	// Pass 2: cache-bust + minify HTML (needs hashes from pass 1).
	for (const abs of files) {
		if (path.extname(abs).toLowerCase() !== '.html') continue;
		const dest = path.join(DIST, path.relative(ROOT, abs));
		let src = fs.readFileSync(dest, 'utf8');

		for (const ref of BUSTABLE) {
			const h = hashes[ref];
			if (!h) continue;
			const esc = ref.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
			src = src.replace(new RegExp(`(href|src)="(${esc})"`, 'g'), `$1="$2?v=${h}"`);
		}

		const min = await minifyHtml(src, {
			collapseWhitespace: true,
			conservativeCollapse: false,
			removeComments: true,
			minifyCSS: true,
			minifyJS: true,
			keepClosingSlash: true,
			caseSensitive: true,
			removeScriptTypeAttributes: true,
			removeStyleLinkTypeAttributes: true,
		});
		fs.writeFileSync(dest, min);
		html++;
	}

	// Pass 3: bump the service-worker cache name so clients refresh.
	const swDest = path.join(DIST, 'sw.js');
	if (fs.existsSync(swDest)) {
		const build = hash8(Buffer.from(Object.values(hashes).join('')));
		let sw = fs.readFileSync(swDest, 'utf8');
		sw = sw.replace(/gcsemate-(static|runtime)-v[\w]+/g, (_, k) => `gcsemate-${k}-${build}`);
		fs.writeFileSync(swDest, sw);
	}

	console.log(
		`\u2705 Build complete in ${Date.now() - t0}ms \u2192 dist/\n` +
		`   ${js} JS minified, ${css} CSS minified, ${html} HTML minified, ${copied} assets copied`,
	);
}

run().catch((err) => {
	console.error('\u274C Build failed:', err);
	process.exit(1);
});
