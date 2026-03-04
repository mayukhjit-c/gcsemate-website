/**
 * Example E2E test for GCSEMate
 * TOOLS IMPROVEMENT #3: TESTING INFRASTRUCTURE
 */

const { test, expect } = require('@playwright/test');

test.describe('GCSEMate E2E Tests', () => {
    test.beforeEach(async ({ page }) => {
        await page.addInitScript(() => {
            try {
                localStorage.clear();
                sessionStorage.clear();
            } catch (_) {
                // best-effort
            }
        });

        await page.goto('/');
        await page.waitForLoadState('domcontentloaded');

        // Ensure app scripts are loaded enough for inline handlers (e.g. onsubmit="handleLogin()")
        await page.waitForFunction(() => typeof window.showAuthPage === 'function', { timeout: 30000 });
        await page.waitForFunction(() => typeof window.handleLogin === 'function', { timeout: 30000 });

        // Wait for the initial loading overlay to get out of the way
        const loadingOverlay = page.locator('#app-loading');
        if (await loadingOverlay.count()) {
            await expect(loadingOverlay).toBeHidden({ timeout: 30000 });
        }

        // Best-effort: the app may load third-party scripts asynchronously.
    });

    test('should load landing page', async ({ page }) => {
        await expect(page).toHaveTitle(/GCSEMate/);
    });

    test('should handle form validation', async ({ page }) => {
        // Open login modal from landing page
        await page.getByRole('button', { name: /sign in/i }).first().click({ force: true });
        const loginModal = page.locator('#login-page');
        await expect(loginModal).toBeVisible();

        // Submit with empty fields to trigger custom JS validation
        await page.locator('#login-button').click();

        const emailError = page.locator('#email-error');
        await expect(emailError).toContainText(/email/i);
    });
});

