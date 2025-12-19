# GCSEMate API Documentation

## Core Functions

### Theme Management

#### `initTheme()`
Initializes dark mode theme system.
- Loads saved theme from localStorage
- Sets up theme toggle buttons
- Updates theme icons

#### `toggleTheme()`
Toggles between light and dark themes.
- Updates `data-theme` attribute on `<html>`
- Saves preference to localStorage
- Announces change to screen readers

### Accessibility Functions

#### `trapFocus(modal)`
Traps keyboard focus within a modal dialog.
- **Parameters:**
  - `modal` (HTMLElement): Modal element to trap focus in
- **Returns:** Cleanup function
- **Usage:** Automatically applied to all modals

#### `announceToScreenReader(message, priority)`
Announces messages to screen readers.
- **Parameters:**
  - `message` (string): Message to announce
  - `priority` (string): 'polite' or 'assertive' (default: 'polite')

#### `enableArrowKeyNavigation(container)`
Enables arrow key navigation in lists/grids.
- **Parameters:**
  - `container` (HTMLElement): Container element

### Search System

#### `AdvancedSearch`
Advanced search functionality object.

**Methods:**
- `search(query, filters)` - Perform search
- `addToHistory(query)` - Add to search history
- `saveSearch(query, filters)` - Save a search
- `getSuggestions(partial)` - Get search suggestions

### Study Progress

#### `StudyProgress`
Study progress tracking system.

**Methods:**
- `startSession(subject)` - Start a study session
- `endSession()` - End current session
- `getStatistics()` - Get study statistics
- `getStreak()` - Get current study streak

### Notification System

#### `NotificationSystem`
In-app notification system.

**Methods:**
- `show(title, message, type, options)` - Show notification
- `markAsRead(id)` - Mark notification as read
- `save()` - Save to localStorage
- `load()` - Load from localStorage

### Performance Utilities

#### `debounce(func, wait)`
Debounce function calls.
- **Parameters:**
  - `func` (Function): Function to debounce
  - `wait` (number): Wait time in milliseconds
- **Returns:** Debounced function

#### `throttle(func, limit)`
Throttle function calls.
- **Parameters:**
  - `func` (Function): Function to throttle
  - `limit` (number): Time limit in milliseconds
- **Returns:** Throttled function

#### `initLazyLoading()`
Initializes lazy loading for images using IntersectionObserver.

## Keyboard Shortcuts

- `?` - Show help page
- `/` - Focus search input
- `g` then `d` - Go to Dashboard
- `g` then `v` - Go to Videos
-- `g` then `b` - Go to Blog
-- `g` then `c` - Go to Calendar
-- `g` then `t` - Go to AI Tutor (Pro only) — REMOVED
-- `Esc` - Close modals

## Event Handlers

### Page Navigation
- `showPage(pageId)` - Navigate to page

### Authentication
- `handleLogin()` - Handle user login
- `handleRegister()` - Handle user registration
- `handleLogout()` - Handle user logout

### File Management
- `fetchAndRenderFiles(folderId)` - Fetch and display files
- `handleNavigation(folderId)` - Navigate to folder

## CSS Custom Properties

### Theme Variables
- `--bg-primary` - Primary background
- `--bg-secondary` - Secondary background
- `--bg-card` - Card background
- `--text-primary` - Primary text color
- `--text-secondary` - Secondary text color
- `--border-color` - Border color

### Semantic Colors
- `--color-success` - Success color
- `--color-warning` - Warning color
- `--color-error` - Error color
- `--color-info` - Info color

### Spacing
- `--spacing-1` through `--spacing-16` - Spacing scale

### Typography
- `--font-weight-light` through `--font-weight-extrabold`
- `--line-height-tight` through `--line-height-loose`

## Service Worker API

### Cache Strategy
- Static assets cached on install
- Runtime caching for API responses
- Network-first for navigation requests

### Events
- `install` - Cache static assets
- `activate` - Clean up old caches
- `fetch` - Serve from cache, fallback to network
- `message` - Handle messages from main thread

