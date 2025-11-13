# Tailwind CSS Build Instructions

## Quick Setup (Recommended)

To build Tailwind CSS for production and remove the CDN warning:

1. **Install Node.js** (if not already installed)
   - Download from: https://nodejs.org/

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Build Tailwind CSS:**
   ```bash
   npm run build:css
   ```

4. **Deploy** - The `tailwind.css` file will now contain all compiled utilities.

## Development Mode

To watch for changes and auto-rebuild:

```bash
npm run watch:css
```

## What This Does

- Scans `index.html` and `app.js` for Tailwind classes
- Compiles only the utilities you actually use
- Creates a minified `tailwind.css` file
- Removes the production warning

## Current Status

The site currently uses a fallback to the Tailwind CDN if `tailwind.css` is not built or is empty. This ensures the site works immediately, but shows a console warning.

After building, the warning will disappear and you'll have a production-ready, optimized CSS file.

