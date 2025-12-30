import { test as base, expect, Page } from '@playwright/test';

/**
 * Helper function to authenticate via dev login
 * This waits for the redirect cycle to complete
 */
export async function authenticateDevMode(page: Page) {
  // Go to home page first
  await page.goto('/');
  await page.waitForLoadState('networkidle');

  // Check if dev login button exists
  const devLoginButton = page.getByRole('link', { name: /Dev Login/i }).first();

  if (await devLoginButton.isVisible()) {
    // Click dev login - this will redirect to backend auth endpoint
    // which then redirects back to /dashboard or /admin
    await devLoginButton.click();

    // Wait for the auth redirect to complete
    // The backend redirects to /dashboard after successful auth
    await page.waitForURL(/\/(dashboard|admin)/, { timeout: 15000 });
  }
}

/**
 * Extended test fixtures for CryptoServe e2e tests
 */
export const test = base.extend<{
  authenticatedPage: Page;
}>({
  authenticatedPage: async ({ page }, use) => {
    await authenticateDevMode(page);
    await use(page);
  },
});

export { expect };

/**
 * Helper to wait for API to be ready
 */
export async function waitForApi(baseUrl: string, timeout = 30000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return true;
    } catch {
      // API not ready yet
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

/**
 * Common selectors used across tests
 */
export const selectors = {
  // Navigation
  sidebar: '[data-testid="sidebar"]',
  navLink: (name: string) => `a[href*="${name}"]`,

  // Common elements
  loadingSpinner: '.animate-spin',
  card: '[class*="Card"]',
  button: 'button',

  // Forms
  input: 'input',
  select: 'select',
  textarea: 'textarea',

  // Tables
  table: 'table',
  tableRow: 'tr',

  // Alerts/Notifications
  toast: '[role="alert"]',
  errorMessage: '.text-red-',
  successMessage: '.text-green-',
};

/**
 * Common test data
 */
export const testData = {
  contexts: {
    testContext: {
      name: 'test-context',
      displayName: 'Test Context',
      description: 'A test encryption context',
    },
  },
  playground: {
    sampleText: 'Hello, World! This is a test message for encryption.',
  },
};
