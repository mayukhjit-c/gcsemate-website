# GCSEMate - Comprehensive Bug Fixes, Issues & Improvements

**Last Updated:** November 24, 2026
**Priority Levels:** 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low
**Status:** ✅ Fixed | 🔄 In Progress | ⏳ Pending

---

## Implementation Summary

All identified issues have been addressed through modular fix files in the `/fixes/` directory:

| Fix Module               | Issues Addressed                 | Status      |
| ------------------------ | -------------------------------- | ----------- |
| `critical-fixes.js`      | CB-001 to CB-005, M-001 to M-005 | ✅ Complete |
| `security-fixes.js`      | S-001 to S-003                   | ✅ Complete |
| `accessibility-fixes.js` | A-001 to A-008                   | ✅ Complete |
| `visual-fixes.js`        | V-001 to V-007, TR-001 to TR-005 | ✅ Complete |
| `mobile-fixes.js`        | MR-001 to MR-007                 | ✅ Complete |
| `animation-fixes.js`     | AN-001 to AN-004                 | ✅ Complete |
| `performance-fixes.js`   | P-001 to P-005                   | ✅ Complete |
| `code-quality-fixes.js`  | CQ-001 to CQ-005                 | ✅ Complete |
| `missing-features.js`    | MF-001 to MF-008                 | ✅ Complete |
| `functional-fixes.js`    | FI-001 to FI-008                 | ✅ Complete |
| `enhancements.js`        | E-001 to E-015                   | ✅ Complete |

---

## Table of Contents

1. [Critical Bugs](#critical-bugs)
2. [Functional Issues](#functional-issues)
3. [Accessibility Issues](#accessibility-issues)
4. [Visual & UI Issues](#visual--ui-issues)
5. [Performance Issues](#performance-issues)
6. [Modal & Dialog Issues](#modal--dialog-issues)
7. [Animation Issues](#animation-issues)
8. [Text Readability Issues](#text-readability-issues)
9. [Mobile & Responsive Issues](#mobile--responsive-issues)
10. [Security Concerns](#security-concerns)
12. [Missing Features](#missing-features)
13. [Enhancement Suggestions](#enhancement-suggestions)

---

## Critical Bugs

### 🔴 CB-001: Modal Close Button Not Working Consistently

**File:** `index.html`, `modal-fixes.js`
**Lines:** Various modal implementations throughout `index.html`
**Problem:** Modal close buttons don't consistently close modals. Some modals lack close buttons entirely.

**Fix Steps:**

1. Open `modal-fixes.js` (lines 1-120)
2. Ensure all modals have a close button with proper event handler
3. Add universal modal close handler:

```javascript
// Add to each modal's close button
onclick = "closeModal('modal-id')";
onclick = "this.closest('.fixed').remove()";
```

4. Ensure ESC key works for all modals (currently partial - line 55-75 in `modal-fixes.js`)
5. Add click-outside-to-close functionality for all modals

---

### 🔴 CB-002: Missing Click Outside Modal Close

**File:** `modal-fixes.js`
**Lines:** 76-82
**Problem:** Click outside modal overlay doesn't consistently close modals.


1. Open `modal-fixes.js` line 76
2. The current implementation only checks for `.modal-backdrop` class
3. Update the click handler to check for all modal overlay patterns:

```javascript
document.addEventListener('click', function (e) {
    const modal = e.target.closest('.fixed.inset-0');
    if (modal && e.target === modal) {
        closeAndRemoveModal(modal);
    }
});
```

---

### 🔴 CB-003: Firebase Operations May Fail Silently

**File:** `app.js`
**Lines:** 1850-1920 (safeFirebaseOperation function)
**Problem:** Some Firebase operations don't show errors to users properly.


1. Review `safeFirebaseOperation` function at line 1850
2. Ensure all Firebase calls use this wrapper
3. Add better error messages for each error type
4. Add toast notifications for all failure scenarios

---

### 🔴 CB-004: Double Form Submission Possible

**File:** `index.html`
**Lines:** 710-750 (login form), 760-800 (register form)
**Problem:** Forms can be submitted multiple times before processing completes.


1. Add `disabled` attribute to submit buttons during processing
2. Add loading state to buttons:

```javascript
// In handleLogin() function
const btn = document.getElementById('login-button');
btn.disabled = true;
btn.innerHTML = '<span class="loader"></span> Logging in...';
// Reset after completion or error
```

3. Implement debounce on form submissions

---

### 🔴 CB-005: Memory Leaks from Unsubscribed Listeners

**File:** `app.js`
**Lines:** 180-220 (listener declarations), 3800-3900 (cleanup)

**Fix Steps:**

1. Review all `onSnapshot` listeners (search for `onSnapshot` in app.js)
2. Ensure each listener has a corresponding unsubscribe in cleanup
3. Add cleanup function call on `beforeunload` event (line 4050)
4. Create a listener registry to track all active subscriptions

---

## Functional Issues

### 🟠 FI-001: Tutorial Modal Shows Even After Completion

**File:** `index.html`
**Lines:** 870-910 (tutorial-overlay)
**Problem:** Tutorial may reappear if localStorage is cleared or on new device.

**Fix Steps:**
1. Store tutorial completion in Firestore user document
2. Update `app.js` to check both localStorage AND Firestore
3. Add a "Don't show again" checkbox option

---

### 🟠 FI-002: Notification Panel Positioning Issues

**File:** `index.html`
**Lines:** 1070-1100 (notification-panel)
**Problem:** Notification panel may overflow viewport on mobile.

**Fix Steps:**

1. Add responsive positioning:

```css
#notification-panel {
    right: 0.5rem;
    max-width: calc(100vw - 1rem);
}
@media (max-width: 640px) {
    #notification-panel {
        right: 0;
        left: 0;
        max-width: none;
    }
}
```

---

### 🟠 FI-003: File Browser Search Not Debounced

**File:** `index.html`, `app.js`
**Lines:** 2020-2040 in index.html (file-search-input)
**Problem:** Search triggers on every keystroke, causing performance issues.

**Fix Steps:**

1. Find the search input handler in `app.js`
2. Wrap the search function with debounce:

```javascript
const debouncedSearch = debounce(function (query) {
    // search logic
}, 300);
document.getElementById('file-search-input').addEventListener('input', e => {
});
```

---

### 🟠 FI-004: View Toggle State Not Persisted

**File:** `index.html`, `app.js`
**Lines:** 2050-2080 (view-toggle buttons)
**Problem:** Grid/List view preference resets on page refresh.

**Fix Steps:**

1. Save preference to localStorage on toggle
2. Load preference on page load:

```javascript
// On toggle click
localStorage.setItem('fileBrowserView', view);
// On page load
const savedView = localStorage.getItem('fileBrowserView') || 'list';
fileBrowserView = savedView;
```

---

### 🟠 FI-005: Download Rate Limit Indicator Not Updating in Real-time

**File:** `app.js`
**Lines:** 67-130 (download rate limit functions)
**Problem:** The download limit indicator doesn't update automatically when time passes.

**Fix Steps:**

1. Add interval to update the indicator:

```javascript
setInterval(updateDownloadLimitIndicator, 1000);
```

2. Add countdown timer display for reset time

---

### 🟡 FI-006: FAQ Search Not Highlighting Matches

**File:** `index.html`
**Lines:** 3470-3480 (faq-search)
**Problem:** Search finds FAQs but doesn't highlight matching text.

**Fix Steps:**

1. Add highlight function:

```javascript
function highlightText(text, query) {
    const regex = new RegExp(`(${query})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
}
```

2. Apply to FAQ answers during search

---

### 🟡 FI-007: Calendar Events Not Showing Time

**File:** `index.html`, `app.js`
**Lines:** Calendar page section
**Problem:** Calendar events only show date, not time.

**Fix Steps:**

1. Add time input to event creation modal
2. Update event display to show time
3. Store time in Firestore with the event

---

### 🟡 FI-008: Profile Picture Upload Has No Preview

**File:** `index.html`
**Lines:** 2420-2450 (profile picture section)
**Problem:** No preview before uploading profile picture.

**Fix Steps:**

1. Add preview element next to upload button
2. Use FileReader to show preview:

```javascript
input.addEventListener('change', e => {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = e => {
            previewImg.src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
});
```

---

## Accessibility Issues

### 🔴 A-001: Missing ARIA Labels on Interactive Elements

**File:** `index.html`
**Lines:** Multiple
**Problem:** Many buttons and links lack proper aria-labels.

**Fix Steps:**

1. Add aria-labels to all icon-only buttons:

```html
<!-- Example: Theme toggle -->
<button aria-label="Toggle dark mode" ...>
    <i class="fas fa-moon"></i>
</button>
```

2. Key locations to fix:
    - Line 955: hamburger-button (has aria-label ✓)
    - Line 1035-1060: navigation links need aria-current
    - All modal close buttons

---

### 🔴 A-002: Missing Focus Trap in Modals

**File:** `comprehensive-fixes.js`
**Lines:** 190-220
**Problem:** Keyboard navigation can escape modal dialogs.

**Fix Steps:**

1. The focus trap exists but may not work for all modals
2. Update the tab trap logic to handle all focusable elements:

```javascript
const focusableSelectors =
    'button, [href], input:not([type="hidden"]), select, textarea, [tabindex]:not([tabindex="-1"])';
```

3. Ensure first focusable element gets focus when modal opens

---

### 🔴 A-003: Color Contrast Issues

**File:** `styles.css`, `index.html`
**Lines:** styles.css 220-280 (color definitions)
**Problem:** Some text/background combinations don't meet WCAG 2.1 AA standards.

**Fix Steps:**

1. Fix gray text on light backgrounds:
    - Change `.text-gray-400` to `.text-gray-600` for body text
    - Change `.text-gray-500` to `.text-gray-700` for important text
2. Update CSS (line 2300 in styles.css):

```css
.text-gray-600 {
    color: #4b5563 !important;
} /* Ensure 4.5:1 contrast */
.text-gray-500 {
    color: #6b7280 !important;
}
```

3. Test with contrast checker tool

---

### 🟠 A-004: Skip Link Not Visible on Focus

**File:** `index.html`, `styles.css`
**Lines:** index.html 386, styles.css 820-835
**Problem:** Skip to content link may not be properly visible.

**Fix Steps:**

1. Update skip link styles in styles.css:

```css
a[href='#page-content'].sr-only:focus {
    position: fixed !important;
    top: 0.5rem !important;
    left: 0.5rem !important;
    z-index: 99999 !important;
    width: auto !important;
    height: auto !important;
    clip: auto !important;
    overflow: visible !important;
}
```

---

### 🟠 A-005: Form Error Messages Not Announced

**File:** `index.html`
**Lines:** 680-700 (form error divs)
**Problem:** Error messages don't have live regions properly configured.

**Fix Steps:**

1. Add role="alert" and aria-live="assertive" to error messages:

```html
<div
    id="email-error"
    class="error-message"
    role="alert"
    aria-live="assertive"
    aria-atomic="true"
></div>
```

2. Ensure error messages are linked to inputs via aria-describedby

---

### 🟠 A-006: Images Missing Alt Text

**File:** `index.html`
**Lines:** Multiple image tags
**Problem:** Some decorative and informative images lack proper alt attributes.

**Fix Steps:**

1. Audit all `<img>` tags
2. Add descriptive alt text for informative images
3. Add `alt=""` and `aria-hidden="true"` for decorative images
4. Key locations:
    - Line 390: Loading logo (add alt)
    - Line 520: Landing page logo
    - Line 2420: Profile pictures

---

### 🟡 A-007: Insufficient Heading Hierarchy

**File:** `index.html`
**Lines:** Various page sections
**Problem:** Some sections skip heading levels (h2 to h4).

**Fix Steps:**

1. Review heading structure on each page
2. Ensure logical hierarchy: h1 → h2 → h3
3. Use CSS for visual styling instead of wrong heading level

---

### 🟡 A-008: Missing Keyboard Shortcuts Help

**File:** `index.html`
**Lines:** 3395-3420 (help page)
**Problem:** Keyboard shortcuts are documented but not easily discoverable.

**Fix Steps:**

1. Add "Press ? for keyboard shortcuts" hint in footer
2. Create keyboard shortcuts modal that appears on `?` press
3. Add visible keyboard shortcut hints next to key actions

---

## Visual & UI Issues

### 🟠 V-001: Inconsistent Button Styles

**File:** `styles.css`, `index.html`
**Lines:** styles.css 420-520 (button styles)
**Problem:** Buttons have inconsistent padding, border-radius, and colors.

**Fix Steps:**

1. Create unified button classes:

```css
.btn {
    padding: 0.75rem 1.5rem;
    border-radius: 0.5rem;
    font-weight: 600;
    transition: all 0.2s ease;
}
.btn-sm {
    padding: 0.5rem 1rem;
    font-size: 0.875rem;
}
.btn-lg {
    padding: 1rem 2rem;
    font-size: 1.125rem;
}
```

2. Replace inline button styles with these classes

---

### 🟠 V-002: Card Shadows Removed Entirely

**File:** `styles.css`
**Lines:** 2210-2230
**Problem:** All shadows removed which reduces visual depth and hierarchy.

**Fix Steps:**

1. Restore subtle shadows:

```css
.card-modern,
.modern-card {
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}
.card-modern:hover {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
```

---

### 🟠 V-003: Logo Has No Loading State

**File:** `index.html`
**Lines:** 390-395, 520-525
**Problem:** Logo shows broken image briefly if slow to load.

**Fix Steps:**

1. Add placeholder/skeleton:

```html
<img
    src="gcsemate%20new.png"
    alt="GCSEMate Logo"
    class="h-12 w-auto"
    style="background: #e5e7eb; min-width: 120px;"
    onload="this.style.background='transparent'"
/>
```

---

### 🟠 V-004: Watermark Overlaps Content

**File:** `index.html`
**Lines:** 405-415 (site-watermark, no-ai-badge)
**Problem:** Fixed watermarks can overlap important content.

**Fix Steps:**

1. Add pointer-events: none (already present, but verify)
2. Increase z-index awareness for modals
3. Consider hiding watermarks in certain views:

```css
.fixed[role='dialog'] ~ #site-watermark,
.fixed[role='dialog'] ~ #no-ai-badge {
    display: none;
}
```

---

### 🟡 V-005: Inconsistent Border Radius

**File:** `styles.css`
**Lines:** Various
**Problem:** Mixed border-radius values: 0.5rem, 0.75rem, 1rem, 12px, 16px.

**Fix Steps:**

1. Define CSS variables:

```css
:root {
    --radius-sm: 0.375rem;
    --radius-md: 0.5rem;
    --radius-lg: 0.75rem;
    --radius-xl: 1rem;
}
```

2. Replace hardcoded values with variables

---

### 🟡 V-006: Empty States Not Styled Consistently

**File:** `index.html`
**Lines:** 2000 (links-empty-state), various others
**Problem:** Empty states have different styles across sections.

**Fix Steps:**

1. Create unified empty state component:

```css
.empty-state {
    text-align: center;
    padding: 3rem 1rem;
}
.empty-state-icon {
    font-size: 3rem;
    color: #9ca3af;
}
.empty-state-title {
    font-size: 1.25rem;
    font-weight: 600;
}
.empty-state-text {
    color: #6b7280;
}
```

---

### 🟡 V-007: Subject Cards Lack Visual Distinction

**File:** `index.html`, `app.js`
**Lines:** Subject icons in app.js (lines 3715-3770)
**Problem:** Subject cards all look similar despite having different icons.

**Fix Steps:**

1. Add unique background gradient per subject:

```javascript
const subjectColors = {
    biology: 'from-green-50 to-emerald-50',
    physics: 'from-amber-50 to-yellow-50',
    chemistry: 'from-cyan-50 to-blue-50',
    // ... etc
};
```

2. Apply to card background

---

## Performance Issues

### 🟠 P-001: Multiple Google Font Requests

**File:** `index.html`
**Lines:** 85-90, 320-325
**Problem:** Google Fonts loaded twice (Inter and Plus Jakarta Sans).

**Fix Steps:**

1. Consolidate font loading:

```html
<link
    href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap"
    rel="stylesheet"
/>
```

2. Remove duplicate imports

---

### 🟠 P-002: Large CSS File Not Minified

**File:** `styles.css`
**Lines:** All (7013 lines)
**Problem:** CSS file is very large and not minified.

**Fix Steps:**

1. Add CSS minification to build process:

```javascript
// In build.js
const CleanCSS = require('clean-css');
const minified = new CleanCSS().minify(css);
```

2. Remove unused CSS rules
3. Split critical CSS for above-the-fold content

---

### 🟠 P-003: All Icons Loaded at Once

**File:** `index.html`
**Lines:** 75-80 (FontAwesome)
**Problem:** Full FontAwesome library loaded even if few icons used.

**Fix Steps:**

1. Use FontAwesome kits with only needed icons
2. Or switch to individual SVG icons:

```html
<!-- Instead of <i class="fas fa-moon"></i> -->
<svg>...</svg>
```

---

### 🟡 P-004: Animation Performance

**File:** `styles.css`
**Lines:** 1700-2000 (animations)
**Problem:** Some animations don't use GPU-accelerated properties.

**Fix Steps:**

1. Use `transform` and `opacity` instead of `left`, `top`, `width`:

```css
/* Bad */
@keyframes slide { left: 0 to left: 100%; }
/* Good */
@keyframes slide { transform: translateX(0) to translateX(100%); }
```

2. Add `will-change` sparingly to animated elements

---

### 🟡 P-005: No Service Worker Caching Strategy

**File:** `sw.js`
**Problem:** Service worker exists but may not have optimal caching.

**Fix Steps:**

1. Implement stale-while-revalidate for static assets
2. Cache Google Fonts
3. Add offline fallback page

---

## Modal & Dialog Issues

### 🔴 M-001: Modals Missing Close on ESC Key (Some)

**File:** `modal-fixes.js`, `app.js`
**Lines:** modal-fixes.js 55-75
**Problem:** Some dynamically created modals don't respond to ESC.

**Fix Steps:**

1. Ensure all modal creation uses standard pattern
2. Add data attribute for ESC handling:

```javascript
modal.setAttribute('data-close-on-esc', 'true');
```

3. Update global ESC handler to check for this attribute

---

### 🔴 M-002: Modal Backdrop Doesn't Block Scrolling

**File:** `styles.css`, `modal-fixes.js`
**Lines:** modal-fixes.js 85-95
**Problem:** Page can scroll behind open modals.

**Fix Steps:**

1. Add body scroll lock when modal opens:

```javascript
document.body.style.overflow = 'hidden';
document.body.style.paddingRight = `${scrollbarWidth}px`;
```

2. Restore on modal close
3. Update `comprehensive-fixes.js` line 130

---

### 🟠 M-003: Modal Animation Inconsistent

**File:** `modal-fixes.js`, `comprehensive-fixes.js`
**Lines:** Various
**Problem:** Some modals fade, some scale, some have no animation.

**Fix Steps:**

1. Create standard modal animation:

```css
.modal-enter {
    opacity: 0;
    transform: scale(0.95);
}
.modal-enter-active {
    opacity: 1;
    transform: scale(1);
    transition: all 0.2s ease-out;
}
```

2. Apply to all modal open/close operations

---

### 🟠 M-004: Nested Modal Focus Issues

**File:** `comprehensive-fixes.js`
**Lines:** 190-220
**Problem:** Opening a modal from another modal breaks focus trap.

**Fix Steps:**

1. Track modal stack:

```javascript
const modalStack = [];
function openModal(id) {
    modalStack.push(id);
    // focus trap
}
function closeModal(id) {
    modalStack.pop();
    // restore focus to previous modal or page
}
```

---

### 🟡 M-005: Modal Max Height Not Responsive

**File:** `styles.css`
**Lines:** 3800-3850 (mobile styles)
**Problem:** Modal content can overflow on small screens.

**Fix Steps:**

1. Add responsive max-height:

```css
.modal-content {
    max-height: calc(100vh - 4rem);
    overflow-y: auto;
}
@media (max-width: 640px) {
    .modal-content {
        max-height: calc(100vh - 2rem);
    }
}
```

---

## Animation Issues

### 🟠 AN-001: Animations Not Respecting prefers-reduced-motion

**File:** `styles.css`
**Lines:** 3520-3530
**Problem:** Some animations still run for users who prefer reduced motion.

**Fix Steps:**

1. The media query exists (line 3520) but doesn't cover all animations
2. Ensure ALL animations are disabled:

```css
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
    }
}
```

---

### 🟠 AN-002: Hero Animation Delay Too Long

**File:** `styles.css`
**Lines:** 2170-2200 (animate-hero-\* classes)
**Problem:** Landing page animations take too long to complete.

**Fix Steps:**

1. Reduce animation delays:

```css
.animate-hero-title {
    animation-delay: 50ms;
}
.animate-hero-subtitle {
    animation-delay: 100ms;
}
.animate-hero-buttons {
    animation-delay: 150ms;
}
```

---

### 🟡 AN-003: Loading Spinner Not Centered on Mobile

**File:** `index.html`, `styles.css`
**Lines:** index.html 388-405 (app-loading)
**Problem:** Loading overlay content can shift on smaller screens.

**Fix Steps:**

1. Ensure centering with flex:

```css
#app-loading {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
}
```

---

### 🟡 AN-004: Star Animation Too Aggressive

**File:** `styles.css`
**Lines:** 2080-2110 (star-icon animations)
**Problem:** Star icon animation may cause layout shift.

**Fix Steps:**

1. Use transform instead of changing size:

```css
.star-icon.starred {
    transform: scale(1.15);
}
.star-icon:hover {
    transform: scale(1.2);
}
```

---

## Text Readability Issues

### 🔴 TR-001: Small Font Size on Mobile

**File:** `styles.css`
**Lines:** 3700-3750 (mobile styles)
**Problem:** Base font size too small on mobile devices.

**Fix Steps:**

1. Update mobile base font:

```css
@media (max-width: 640px) {
    body {
        font-size: 16px;
    }
    .text-sm {
        font-size: 14px;
    }
    .text-xs {
        font-size: 13px;
    }
}
```

---

### 🔴 TR-002: Low Contrast Placeholder Text

**File:** `styles.css`
**Lines:** 2330-2340
**Problem:** Placeholder text is too light to read.

**Fix Steps:**

1. Update placeholder styles:

```css
::placeholder {
    color: #6b7280; /* Darker gray */
    opacity: 1;
}
```

---

### 🟠 TR-003: Line Height Too Tight in Cards

**File:** `styles.css`
**Lines:** 290-310 (card styles)
**Problem:** Card text is cramped.

**Fix Steps:**

1. Update card text line-height:

```css
.card-modern p,
.modern-card p {
    line-height: 1.6;
}
```

---

### 🟠 TR-004: Long Words Overflow Containers

**File:** `styles.css`
**Problem:** Long email addresses or URLs break layouts.

**Fix Steps:**

1. Add word-wrap utilities:

```css
.break-words {
    word-wrap: break-word;
    overflow-wrap: break-word;
    hyphens: auto;
}
```

2. Apply to email displays and URL fields

---

### 🟡 TR-005: Blog Content Hard to Read

**File:** `styles.css`
**Lines:** 1485-1540 (prose styles)
**Problem:** Blog post body text lacks optimal reading experience.

**Fix Steps:**

1. Improve blog typography:

```css
.blog-content {
    font-size: 1.125rem;
    line-height: 1.8;
    max-width: 65ch;
    margin: 0 auto;
}
.blog-content p {
    margin-bottom: 1.5rem;
}
.blog-content h2 {
    margin-top: 2.5rem;
}
```

---

## Mobile & Responsive Issues

### 🔴 MR-001: Navigation Breaks on Small Screens

**File:** `index.html`, `styles.css`
**Lines:** index.html 950-1000 (header nav)
**Problem:** Desktop navigation shows on medium screens causing overflow.

**Fix Steps:**

1. Update breakpoint:

```css
/* Change lg:flex to xl:flex for desktop nav */
@media (min-width: 1280px) {
    .desktop-nav {
        display: flex;
    }
}
@media (max-width: 1279px) {
    .desktop-nav {
        display: none;
    }
    .mobile-menu-button {
        display: block;
    }
}
```

---

### 🔴 MR-002: Touch Targets Too Small

**File:** `index.html`, `styles.css`
**Lines:** Various buttons and links
**Problem:** Many buttons don't meet 44x44px minimum touch target.

**Fix Steps:**

1. Update button minimum sizes:

```css
button,
a,
[role='button'] {
    min-height: 44px;
    min-width: 44px;
}
```

2. Increase padding on small buttons

---

### 🟠 MR-003: Mobile Menu Has No Back Button for Submenus

**File:** `index.html`
**Lines:** 1105-1200 (mobile-menu)
**Problem:** No visual way to go back if nested navigation exists.

**Fix Steps:**

1. Add back button for any submenu
2. Or flatten the navigation structure

---

### 🟠 MR-004: Table Overflows on Mobile

**File:** `styles.css`
**Lines:** 3860-3890
**Problem:** Tables don't scroll horizontally properly.

**Fix Steps:**

1. Wrap tables:

```html
<div class="table-wrapper overflow-x-auto">
    <table>
        ...
    </table>
</div>
```

2. Style wrapper:

```css
.table-wrapper {
    -webkit-overflow-scrolling: touch;
    scrollbar-width: thin;
}
```

---

### 🟠 MR-005: Form Inputs Zoom on iOS

**File:** `styles.css`
**Lines:** 3790 (mobile styles)
**Problem:** Font size < 16px causes iOS to zoom on input focus.

**Fix Steps:**

1. Ensure all inputs have 16px minimum:

```css
input,
textarea,
select {
    font-size: 16px !important;
}
```

(Already partially implemented but verify all inputs)

---

### 🟡 MR-006: Landscape Orientation Issues

**File:** `styles.css`
**Problem:** No landscape-specific optimizations.

**Fix Steps:**

1. Add landscape media queries:

```css
@media (orientation: landscape) and (max-height: 500px) {
    header {
        padding: 0.5rem 1rem;
    }
    .page {
        padding: 0.5rem;
    }
}
```

---

### 🟡 MR-007: Safe Area Insets Not Applied Everywhere

**File:** `styles.css`, `index.html`
**Lines:** styles.css 210-220
**Problem:** Not all elements respect notch/home indicator areas.

**Fix Steps:**

1. Apply safe area insets to key elements:

```css
.fixed.bottom-0 {
    padding-bottom: env(safe-area-inset-bottom, 0);
}
header {
    padding-top: env(safe-area-inset-top, 0);
}
```

---

## Security Concerns

### 🟠 S-001: API Keys Exposed in Frontend

**File:** `app.js`, `index.html`
**Lines:** index.html 310-315, app.js 3680
**Problem:** reCAPTCHA site key is exposed (which is expected, but other keys need review).

**Fix Steps:**

1. Audit all scripts for hardcoded keys
2. Ensure only public keys are in frontend
3. Move sensitive operations to backend/Firebase Functions

---

### 🟠 S-002: No Rate Limiting on Auth Attempts

**File:** `app.js`
**Problem:** Brute force attacks possible on login.

**Fix Steps:**

1. Implement rate limiting:

```javascript
const authAttempts = {};
function checkRateLimit(email) {
    const now = Date.now();
    const attempts = authAttempts[email] || [];
    const recentAttempts = attempts.filter(t => now - t < 300000);
    if (recentAttempts.length >= 5) {
        return false; // Too many attempts
    }
    authAttempts[email] = [...recentAttempts, now];
    return true;
}
```

---

### 🟡 S-003: No CSRF Protection on Forms

**File:** `index.html`
**Problem:** Forms lack CSRF tokens (relies on Firebase Auth).

**Fix Steps:**

1. If adding custom backend endpoints, include CSRF tokens
2. For Firebase-only operations, current setup is acceptable

---

## Code Quality Issues

### 🟠 CQ-001: Large Monolithic Files

**File:** `app.js`, `styles.css`
**Problem:** app.js is 22,000+ lines, styles.css is 7,000+ lines.

**Fix Steps:**

1. Split app.js into modules:
    - auth.js
    - firestore.js
    - ui.js
    - utils.js
    - pages/\*.js
2. Split styles.css:
    - base.css
    - components.css
    - pages.css
    - utilities.css

---

### 🟠 CQ-002: Inconsistent Function Documentation

**File:** `app.js`
**Problem:** Many functions lack JSDoc comments.

**Fix Steps:**

1. Add JSDoc to all public functions:

```javascript
/**
 * Shows a toast notification
 * @param {string} message - The message to display
 * @param {'success'|'error'|'warning'|'info'} type - Toast type
 * @param {number} duration - Duration in milliseconds
 */
function showToast(message, type = 'info', duration = 3000) {
```

---

### 🟠 CQ-003: Duplicate CSS Rules

**File:** `styles.css`
**Problem:** Same styles defined multiple times.

**Fix Steps:**

1. Search for duplicate selectors
2. Consolidate rules
3. Use CSS variables for repeated values

---

### 🟡 CQ-004: Magic Numbers in JavaScript

**File:** `app.js`
**Problem:** Hardcoded numbers without explanation.

**Fix Steps:**

1. Create constants file:

```javascript
const CONFIG = {
    DOWNLOAD_RATE_LIMIT: 3,
    RATE_LIMIT_WINDOW_MS: 60000,
    DEBOUNCE_DELAY_MS: 300,
    TOAST_DURATION_MS: 3000,
    // etc.
};
```

---

### 🟡 CQ-005: No Unit Tests

**File:** `tests/`
**Problem:** Minimal test coverage.

**Fix Steps:**

1. Add Jest tests for utility functions
2. Add integration tests for critical flows
3. Set up CI/CD to run tests on commit

---

## Missing Features

### 🟠 MF-001: No Dark Mode Toggle in Header

**File:** `index.html`
**Lines:** 1050-1060 (theme-toggle exists but may not be visible)
**Problem:** Theme toggle exists but is hard to find.

**Fix Steps:**

1. Make theme toggle more prominent in header
2. Add tooltip explaining the feature
3. Show current theme state (sun/moon icon based on mode)

---

### 🟠 MF-002: No Print Styles

**File:** `styles.css`
**Problem:** Printing pages shows navigation, colors, etc.

**Fix Steps:**

1. Add print media query:

```css
@media print {
    nav,
    header,
    footer,
    #site-watermark,
    #no-ai-badge {
        display: none;
    }
    body {
        background: white;
        color: black;
    }
    a {
        color: black;
        text-decoration: underline;
    }
    .page {
        padding: 0;
    }
}
```

---

### 🟠 MF-003: No Offline Indicator

**File:** `index.html`
**Lines:** 910-930 (offline-status-banner exists)
**Problem:** Offline banner may not show consistently.

**Fix Steps:**

1. Ensure offline detection is robust:

```javascript
window.addEventListener('online', updateOnlineStatus);
window.addEventListener('offline', updateOnlineStatus);
function updateOnlineStatus() {
    const banner = document.getElementById('offline-status-banner');
    banner.classList.toggle('hidden', navigator.onLine);
}
```

---

### 🟡 MF-004: No Breadcrumb on Mobile

**File:** `index.html`
**Lines:** 2015-2020 (breadcrumb)
**Problem:** Breadcrumb may be hard to see on mobile.

**Fix Steps:**

1. Add horizontal scroll for breadcrumb
2. Or show only last 2-3 items with ellipsis

---

### 🟡 MF-005: No Session Timeout Warning

**File:** `app.js`
**Problem:** Users aren't warned before session expires.

**Fix Steps:**

1. Add session timeout tracking
2. Show warning 5 minutes before expiry
3. Allow user to extend session

---

### 🟡 MF-006: No Export/Download for Calendar Events

**File:** `index.html`, `app.js`
**Problem:** Users can't export their calendar events.

**Fix Steps:**

1. Add "Export to iCal" button
2. Generate .ics file format
3. Trigger download

---

### 🟢 MF-007: No Keyboard Navigation Guide

**File:** `index.html`
**Problem:** Keyboard shortcuts exist but aren't discoverable.

**Fix Steps:**

1. Add keyboard shortcuts modal (trigger with `?`)
2. Add hints in tooltips

---

### 🟢 MF-008: No Progress Indicator for Long Operations

**File:** `app.js`
**Problem:** Long operations (file downloads, etc.) don't show progress.

**Fix Steps:**

1. Add progress bar component
2. Update for operations that support progress events

---

## Enhancement Suggestions

### 🟢 E-001: Add Page Load Progress Bar

**Description:** Show a thin progress bar at top of page during navigation.

**Implementation:**

```javascript
// Create progress bar element
const progressBar = document.createElement('div');
progressBar.id = 'page-progress';
progressBar.innerHTML = '<div class="progress-fill"></div>';
document.body.prepend(progressBar);

// Animate during page loads
function startProgress() {
    document.querySelector('.progress-fill').style.width = '70%';
}
function completeProgress() {
    document.querySelector('.progress-fill').style.width = '100%';
    setTimeout(() => {
        document.querySelector('.progress-fill').style.width = '0%';
    }, 200);
}
```

---

### 🟢 E-002: Add Smooth Page Transitions

**Description:** Animate between page views for a polished feel.

**Implementation:**

1. Add exit animation class before hiding page
2. Add enter animation class when showing page
3. Coordinate timing with requestAnimationFrame

---

### 🟢 E-003: Add Toast Queue System

**Description:** Queue multiple toasts instead of overlapping.

**Implementation:**

```javascript
const toastQueue = [];
function showToast(message, type) {
    toastQueue.push({ message, type });
    if (toastQueue.length === 1) {
        displayNextToast();
    }
}
function displayNextToast() {
    if (toastQueue.length === 0) return;
    const { message, type } = toastQueue[0];
    // Display toast
    // On hide, shift queue and call displayNextToast
}
```

---

### 🟢 E-004: Add File Type Icons

**Description:** Show appropriate icons for different file types.

**Implementation:**

```javascript
const fileTypeIcons = {
    pdf: 'fa-file-pdf',
    doc: 'fa-file-word',
    docx: 'fa-file-word',
    xls: 'fa-file-excel',
    xlsx: 'fa-file-excel',
    ppt: 'fa-file-powerpoint',
    pptx: 'fa-file-powerpoint',
    jpg: 'fa-file-image',
    png: 'fa-file-image',
    mp4: 'fa-file-video',
    mp3: 'fa-file-audio',
    default: 'fa-file',
};
```

---

### 🟢 E-005: Add Search Results Highlighting

**Description:** Highlight matching text in search results.

**Implementation:**

```javascript
function highlightMatches(text, query) {
    const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
    return text.replace(regex, '<mark class="bg-yellow-200">$1</mark>');
}
```

---

### 🟢 E-006: Add Recent Files Section

**Description:** Show recently accessed files for quick access.

**Implementation:**

1. Track file opens in localStorage
2. Store last 10 files with timestamps
3. Display in dashboard or sidebar

---

### 🟢 E-007: Add Study Time Tracking

**Description:** Show how long users spend on each subject.

**Implementation:**

1. Track page visibility and active subject
2. Store cumulative time in Firestore
3. Display weekly/monthly stats

---

### 🟢 E-008: Add Confetti Animation for Achievements

**Description:** Celebrate milestones with confetti animation.

**Implementation:**

```javascript
function triggerConfetti() {
    // Use canvas-confetti library or custom implementation
    confetti({
        particleCount: 100,
        spread: 70,
        origin: { y: 0.6 },
    });
}
```

---

### 🟢 E-009: Add Skeleton Loading States

**Description:** Show skeleton placeholders while content loads.

**Implementation:**

```html
<div class="skeleton-loader">
    <div class="skeleton-avatar"></div>
    <div class="skeleton-text"></div>
    <div class="skeleton-text w-3/4"></div>
</div>
```

---

### 🟢 E-010: Add Copy to Clipboard Feedback

**Description:** Show visual feedback when copying text.

**Implementation:**

```javascript
async function copyToClipboard(text, element) {
    await navigator.clipboard.writeText(text);
    const original = element.innerHTML;
    element.innerHTML = '<i class="fas fa-check"></i> Copied!';
    setTimeout(() => (element.innerHTML = original), 2000);
}
```

---

### 🟢 E-011: Add Lazy Loading for Images

**Description:** Defer loading images until they're near viewport.

**Implementation:**

```html
<img loading="lazy" src="..." alt="..." />
```

Or use Intersection Observer for more control.

---

### 🟢 E-012: Add Form Autosave

**Description:** Automatically save form drafts to localStorage.

**Implementation:**

```javascript
function setupAutosave(formId) {
    const form = document.getElementById(formId);
    const saveKey = `draft_${formId}`;

    // Load draft
    const draft = localStorage.getItem(saveKey);
    if (draft) populateForm(form, JSON.parse(draft));

    // Save on change
    form.addEventListener(
        'input',
        debounce(() => {
            localStorage.setItem(saveKey, JSON.stringify(getFormData(form)));
        }, 1000)
    );

    // Clear on submit
    form.addEventListener('submit', () => {
        localStorage.removeItem(saveKey);
    });
}
```

---

### 🟢 E-013: Add Drag and Drop File Upload

**Description:** Allow drag and drop for file uploads where applicable.

**Implementation:**

```javascript
dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});
dropZone.addEventListener('drop', e => {
    e.preventDefault();
    const files = e.dataTransfer.files;
    handleFiles(files);
});
```

---

### 🟢 E-014: Add Pull to Refresh on Mobile

**Description:** Allow pull-to-refresh gesture on mobile devices.

**Implementation:**

1. Detect touch start and move at top of page
2. Show refresh indicator
3. Trigger refresh on release

---

### 🟢 E-015: Add Command Palette

**Description:** Add a command palette for power users (Ctrl+K).

**Implementation:**

1. Create modal with search input
2. List available actions
3. Filter on type
4. Execute on selection

---

---

## Priority Matrix

| Priority    | Count | Example Issues                             |
| ----------- | ----- | ------------------------------------------ |
| 🔴 Critical | 12    | Modal close, Memory leaks, Form submission |
| 🟠 High     | 28    | Performance, Accessibility, Mobile         |
| 🟡 Medium   | 22    | Visual polish, UX improvements             |
| 🟢 Low      | 15    | Nice-to-have features, enhancements        |

---

## Quick Wins (Can Fix in < 30 minutes)

1. Add `aria-label` to icon buttons
2. Fix placeholder contrast
3. Add `loading="lazy"` to images
4. Consolidate Google Fonts request
5. Add print styles
6. Fix mobile font sizes
7. Add ESC key to all modals
8. Fix double form submission

---

## Notes

- Always test changes on Chrome, Firefox, Safari, and Edge
- Test mobile on iOS Safari and Android Chrome
- Run Lighthouse audit before/after major changes
- Keep accessibility score above 90
- Keep performance score above 80

---

**Document Maintained By:** Development Team
**Review Frequency:** Weekly
