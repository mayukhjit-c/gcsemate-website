# GCSEMate Developer Guide

## Getting Started

### Prerequisites
- Node.js 18+ and npm 9+
- Git
- Code editor (VS Code recommended)

### Installation

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## Project Structure

```
gcsemate-website/
├── index.html          # Main HTML file
├── app.js             # Main JavaScript application
├── styles.css         # All styles and themes
├── sw.js              # Service Worker for offline support
├── package.json       # Dependencies and scripts
├── vite.config.js     # Build configuration
├── jest.config.js      # Test configuration
├── .eslintrc.json     # ESLint configuration
├── .prettierrc.json   # Prettier configuration
└── docs/              # Documentation
```

## Development Workflow

### Code Quality

```bash
# Lint code
npm run lint

# Fix linting issues
npm run lint:fix

# Format code
npm run format

# Check formatting
npm run format:check
```

### Testing

```bash
# Run unit tests
npm run test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage

# Run E2E tests
npm run test:e2e

# Run accessibility tests
npm run test:a11y
```

## Architecture

### State Management
- Uses Firebase for backend state
- LocalStorage for client-side preferences
- No global state management library (vanilla JS)

### Component System
- Custom component functions in `app.js`
- Reusable utility functions
- Event-driven architecture

### Styling
- CSS Custom Properties for theming
- Dark mode support via `data-theme` attribute
- Responsive design with mobile-first approach

## Key Features

### Dark Mode
- Toggle via theme button in header
- Persists in localStorage
- Smooth transitions

### Accessibility
- ARIA labels on all interactive elements
- Keyboard navigation support
- Screen reader optimizations
- Focus management

### Performance
- Lazy loading for images
- Service Worker for offline support
- Code splitting ready
- Debounced/throttled functions

## API Integration

### Firebase
- Authentication
- Firestore database
- Storage

### External APIs
- Google Drive API
- YouTube API
- Groq API (AI Tutor)

## Deployment

### Cloudflare Pages
- Automatic deployment via GitHub Actions
- Environment variables in Cloudflare dashboard
- Custom domain configuration

## Contributing

1. Create a feature branch
2. Make your changes
3. Run tests and linting
4. Submit a pull request

## Code Style

- Use JSDoc comments for all functions
- Follow ESLint rules
- Use Prettier for formatting
- Write descriptive variable names

## Troubleshooting

### Common Issues

**Service Worker not updating:**
- Clear browser cache
- Unregister service worker in DevTools

**Dark mode not working:**
- Check localStorage for 'theme' key
- Verify CSS variables are loaded

**Tests failing:**
- Run `npm install` to update dependencies
- Check Node.js version (18+)

## Resources

- [Firebase Documentation](https://firebase.google.com/docs)
- [WCAG Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [MDN Web Docs](https://developer.mozilla.org/)

