# GCSEMate – Build Instructions

## One-time setup

1. Install Node.js 18+ (https://nodejs.org/)
2. From the project root:
   ```bash
   npm install
   ```
   This installs the new build tools: **esbuild** (JS/CSS minify) and
   **html-minifier-terser** (HTML minify), alongside your existing deps.

## Production build

```bash
npm run build
```

This runs two steps:

1. `build:css` – compiles Tailwind utilities into `tailwind.css` (purges unused
   classes, removes the CDN console warning).
2. `build:js` (`node build.js`) – produces an optimised **`dist/`** folder:
   - Mirrors the entire project (images, `assets/`, `functions/`, subpages,
     rules) so nothing is missed.
   - Minifies every `.js` with esbuild and **drops `console.*` / `debugger`**
     from the app bundle (banners in `security.js` and logging in `sw.js` are
     preserved on purpose).
   - Minifies every `.css` with esbuild.
   - Minifies every `.html` (collapses whitespace, inlines/minifies inline CSS
     & JS, strips comments).
   - Appends a content-hash `?v=<hash>` to the local `app.js`, `styles.css`,
     `tailwind.css`, and `security.js` references in your HTML so browsers fetch
     fresh files immediately after each deploy — without breaking long caches.
   - Bumps the service-worker cache name to the new build hash.

## Deploy

Deploy the generated **`dist/`** folder (not the source root).
The dev notes (`README.md`, `*_DOCUMENTATION.md`, `todo.md`, etc.) and tooling
configs are intentionally excluded from `dist/`.

## Local development

```bash
npm run dev        # Vite dev server on http://localhost:3000
npm run watch:css  # rebuild tailwind.css on change
```
