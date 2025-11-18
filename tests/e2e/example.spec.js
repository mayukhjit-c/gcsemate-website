/**
 * Example E2E test for GCSEMate
 * TOOLS IMPROVEMENT #3: TESTING INFRASTRUCTURE
 */

const { test, expect } = require('@playwright/test');

test.describe('GCSEMate E2E Tests', () => {
    test.beforeEach(async ({ page }) => {
        await page.goto('/');
    });

    test('should load landing page', async ({ page }) => {
        await expect(page).toHaveTitle(/GCSEMate/);
    });

    test('should toggle dark mode', async ({ page }) => {
        // Wait for theme toggle to be visible
        const themeToggle = page.locator('#theme-toggle');
        await themeToggle.waitFor({ state: 'visible' });

        // Click theme toggle
        await themeToggle.click();

        // Check if dark theme is applied
        const html = page.locator('html');
        await expect(html).toHaveAttribute('data-theme', 'dark');
    });

    test('should navigate with keyboard shortcuts', async ({ page }) => {
        // Press '?' to open help
        await page.keyboard.press('?');
        await expect(page.locator('#help-page')).toBeVisible();

        // Press 'g' then 'd' to go to dashboard
        await page.keyboard.press('g');
        await page.keyboard.press('d');
        await expect(page.locator('#subject-dashboard-page')).toBeVisible();
    });

    test('should handle form validation', async ({ page }) => {
        // Try to submit empty login form
        const loginButton = page.locator('#login-button');
        await loginButton.click();

        // Check for validation messages
        const emailError = page.locator('#email-error');
        await expect(emailError).toBeVisible();
    });
});

