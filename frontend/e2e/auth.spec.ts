import { test, expect } from '@playwright/test';

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Start from the home page
    await page.goto('/');
  });

  test('should display login page with dev login option', async ({ page }) => {
    // Check that the page loads
    await expect(page).toHaveTitle(/CryptoServe/i);

    // Look for dev login button (in dev mode)
    const devLoginButton = page.getByRole('link', { name: /Dev Login|Get Started/i });
    await expect(devLoginButton.first()).toBeVisible();
  });

  test('should show CryptoServe branding', async ({ page }) => {
    // Check for branding - use exact match to avoid matching code examples
    await expect(page.getByText('CryptoServe', { exact: true })).toBeVisible();
    await expect(page.getByText('Zero-Config Cryptography')).toBeVisible();
  });

  test('should show admin sidebar after navigating to admin', async ({ page }) => {
    // Navigate directly to admin (assumes dev mode auto-login)
    await page.goto('/admin');

    // Wait for page to load
    await page.waitForLoadState('networkidle');

    // Check for sidebar navigation items
    const sidebar = page.locator('nav, aside').first();
    await expect(sidebar).toBeVisible();
  });

  test('should show feature cards on landing page', async ({ page }) => {
    // Check for feature cards
    await expect(page.getByText('Personalized SDKs')).toBeVisible();
    await expect(page.getByText('Context-Based Policies')).toBeVisible();
    await expect(page.getByText('Full Audit Trail')).toBeVisible();
  });
});
