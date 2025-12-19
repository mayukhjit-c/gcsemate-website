# GCSEMate Architecture

## Overview

GCSEMate is a single-page application (SPA) built with vanilla JavaScript, HTML, and CSS. It uses Firebase for backend services and follows a component-based architecture.

## Architecture Decisions

### ADR-001: Vanilla JavaScript over Framework
**Decision:** Use vanilla JavaScript instead of React/Vue/Angular
**Rationale:**
- Smaller bundle size
- Faster initial load
- No framework learning curve
- Full control over implementation

### ADR-002: CSS Custom Properties for Theming
**Decision:** Use CSS custom properties for theming
**Rationale:**
- Native browser support
- Easy theme switching
- No JavaScript required for theme changes
- Better performance

### ADR-003: Service Worker for Offline Support
**Decision:** Implement Service Worker for offline functionality
**Rationale:**
- Progressive Web App capabilities
- Better user experience offline
- Reduced server load
- Caching strategy

### ADR-004: localStorage for Client State
**Decision:** Use localStorage for client-side preferences
**Rationale:**
- Simple and fast
- No backend required
- Persists across sessions
- Sufficient for user preferences

## Component Structure

### Page Components
- `subject-dashboard-page` - Subject selection
-- `videos-page` - Video playlists
-- `blog-page` - Blog posts
-- `calendar-page` - Calendar view
-- `ai-tutor-page` - AI tutoring (REMOVED)
-- `account-settings-page` - User settings

### Modal Components
- `confirmation-modal` - Confirmation dialogs
- `upgrade-modal` - Upgrade prompts
- `preview-modal` - File previews

### Utility Functions
- Authentication helpers
- File management
- Search functionality
- Theme management
- Accessibility helpers

## Data Flow

1. User interaction triggers event
2. Event handler processes action
3. State updated (Firebase/localStorage)
4. UI updated via DOM manipulation
5. Visual feedback provided

## State Management

### Global State
- `currentUser` - Current authenticated user
- `currentFolderFiles` - Currently displayed files
- `path` - Current navigation path

### Local State
- Theme preference (localStorage)
- User preferences (localStorage)
- Search history (localStorage)
- Study sessions (localStorage)

## Performance Optimizations

1. **Lazy Loading**
   - Images loaded on demand
   - IntersectionObserver API

2. **Debouncing/Throttling**
   - Search input debounced
   - Scroll events throttled

3. **Caching**
   - Service Worker caching
   - localStorage for preferences

4. **Code Splitting**
   - Ready for Vite code splitting
   - Lazy load modules

## Security

- Firebase Authentication
- reCAPTCHA Enterprise
- Input sanitization
- XSS prevention
- CSRF protection

## Accessibility

- ARIA labels throughout
- Keyboard navigation
- Screen reader support
- Focus management
- Color contrast compliance

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## Future Considerations

- TypeScript migration
- Component library
- State management library (if needed)
- Internationalization (i18n)

