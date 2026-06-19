# GCSEMate – `app.js` Code Audit

_Static analysis of `app.js` (29,753 lines / ~1.3 MB). No runtime profiling._

## Structure

Hand-written single-page app, organised into ~21 banner-delimited sections.
State lives in module-scoped `let` globals (`currentUser`, `path`, `allUsers`,
`allBlogPosts`, `allLessons`…). **123 `window.X =` exports** wire functions to
inline `onclick=""` handlers in generated HTML.

| Metric | Count |
|---|---|
| Named functions | 882 |
| Arrow-assigned functions | 329 |
| `addEventListener` / `removeEventListener` | 370 / 36 |
| `setInterval` / `clearInterval` | 17 / 24 |
| `getElementById` (distinct IDs) | 1,146 (671) |
| `.innerHTML =` (dynamic) | 206 (105) |
| `textContent =` | 401 |
| `try` blocks / empty `catch {}` | 462 / 196 |
| `console.*` | 139 |

## What's already solid

- **No `var`** — 100% `let`/`const`.
- **Equality is clean** — the only `==` hits are Firestore `.where()` query
  strings, plus one intentional `raw == null` check.
- **No `eval`, `new Function`, or `document.write`.**
- **No secrets in `app.js`** (no Stripe `sk_`/`pk_`, no inline `firebaseConfig`).
- **Strong escaping discipline**: `escapeHTML` (224×), `escapeHtml` (24×),
  `sanitize` (33×).
- Dev-only `debugLog()` gate already present.

## Issues

### 🔴 High

1. **Duplicate function definitions (conflicting)** — _FIXED, see below._
   `showToast`, `debounce`, `throttle` were each declared twice at global
   scope; the later declaration silently won.

### 🟠 Medium

2. **XSS surface — reviewed.** 206 `.innerHTML =`, of which 105 are dynamic and
   23 reference user/remote-ish data. Manual review of the candidates:
   - File/folder names (`highlightMatch`) — **SAFE**: escaped via `escapeHtml()`
     before injection.
   - Most "dynamic" sinks are static template markup (empty states, spinners).
   - **Worth hardening**: `verification-email-display` interpolates `${email}`
     directly (self-view only → low severity), and toast `title`/`message` are
     injected raw — fine for app-controlled strings, but escape if ever fed
     remote/user content.
3. **196 empty `catch {}` (42% of all try blocks)** swallow errors silently.
   Many are legitimate best-effort (localStorage in private mode); the rest
   should at least `debugLog`.
4. **DOM re-query churn**: hot elements looked up repeatedly — `#landing-page`
   ×11, `#blog-post-content` ×11, `#lesson-content` ×10, `#main-app` ×9,
   `#login-page` ×9. Cache references.
5. **Listener/timer balance**: 370 `addEventListener` vs 36 `removeEventListener`.
   Verify SPA section re-renders clean up listeners/intervals.

### 🟡 Low

6. **~182 repeated 6-line code windows** — moderate copy-paste; consolidate into
   helpers.
7. **139 raw `console.*`** — already stripped from production by the build.
8. **123 `window.*` globals** — consider a single `window.GCSEMate = {}` namespace.

## Fixes applied in this pass

| Function | Removed (dead) | Kept (live) | Effect |
|---|---|---|---|
| `showToast` | L12837 `(message, type, duration)` | L22835 `(message, type, options)` | None — live version already shims numeric duration |
| `debounce` | L1966 (shared-map variant) | L16431 (closure variant) | None — closure variant already active |
| `throttle` | L1981 (leading+trailing) | L4559 (shared-map variant) | None — shared-map variant already active |

All three removals are behaviour-preserving (the later declaration already won
at runtime). Validated with `node --check`. ~3.7 KB removed.

## Recommended next steps (not yet done)

1. Add minimal logging to the meaningful empty `catch` blocks.
2. Cache the hot `getElementById` lookups.
3. Audit SPA re-render paths for listener/interval cleanup.
4. Consolidate the repeated 6-line blocks into shared helpers.
