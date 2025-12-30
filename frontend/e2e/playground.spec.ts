import { test, expect } from '@playwright/test';
import { authenticateDevMode } from './fixtures';

test.describe('Crypto Playground', () => {
  test.beforeEach(async ({ page }) => {
    // Authenticate first
    await authenticateDevMode(page);
    // Go to playground page
    await page.goto('/admin/playground');
    await page.waitForLoadState('networkidle');
  });

  test('should display playground page', async ({ page }) => {
    // Check page title
    await expect(page.getByText('Crypto Playground').first()).toBeVisible();

    // Check for info banner
    await expect(page.getByText('Interactive Testing')).toBeVisible();
  });

  test('should have encrypt/decrypt toggle buttons', async ({ page }) => {
    // Check for operation toggle buttons - they contain Lock/Unlock icons and text
    await expect(page.getByRole('button', { name: /Encrypt/i }).first()).toBeVisible();
    await expect(page.getByRole('button', { name: /Decrypt/i }).first()).toBeVisible();
  });

  test('should have context selector', async ({ page }) => {
    // Check for context dropdown
    const contextSelector = page.locator('select').first();
    await expect(contextSelector).toBeVisible();
  });

  test('should have input textarea', async ({ page }) => {
    // Check for data input
    const inputArea = page.locator('textarea');
    await expect(inputArea).toBeVisible();
  });

  test('should have execute button', async ({ page }) => {
    // Check for execute button - it says "Execute Encryption" or "Execute Decryption"
    const executeButton = page.getByRole('button', { name: /Execute/i });
    await expect(executeButton).toBeVisible();
  });

  test('should disable execute button when input is empty', async ({ page }) => {
    // Execute button should be disabled initially when input is empty
    const executeButton = page.getByRole('button', { name: /Execute/i });
    await expect(executeButton).toBeDisabled();
  });

  test('should enable execute button when input is provided', async ({ page }) => {
    // Fill in input
    const inputArea = page.locator('textarea');
    await inputArea.fill('Test message for encryption');

    // Execute button should be enabled
    const executeButton = page.getByRole('button', { name: /Execute/i });
    await expect(executeButton).toBeEnabled();
  });

  test('should toggle between encrypt and decrypt modes', async ({ page }) => {
    // By default should be in encrypt mode
    const encryptButton = page.getByRole('button', { name: /Encrypt/i }).first();
    const decryptButton = page.getByRole('button', { name: /Decrypt/i }).first();

    // Click decrypt button
    await decryptButton.click();

    // Execute button should say "Execute Decryption"
    await expect(page.getByRole('button', { name: /Execute Decryption/i })).toBeVisible();

    // Click encrypt button
    await encryptButton.click();

    // Execute button should say "Execute Encryption"
    await expect(page.getByRole('button', { name: /Execute Encryption/i })).toBeVisible();
  });

  test('should show SDK code section', async ({ page }) => {
    // Look for SDK code section
    await expect(page.getByText('SDK Code Equivalent')).toBeVisible();
  });

  test('should expand SDK code section when clicked', async ({ page }) => {
    // Click SDK section header
    const sdkSection = page.getByText('SDK Code Equivalent');
    await sdkSection.click();

    // Should show Python code
    await expect(page.getByText('Python SDK')).toBeVisible();
    await expect(page.getByText(/crypto\.encrypt_string|crypto\.decrypt_string/)).toBeVisible();
  });

  test('should show quick tips', async ({ page }) => {
    // Scroll to bottom
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(300);

    // Check for tip cards
    await expect(page.getByText('Encryption').last()).toBeVisible();
    await expect(page.getByText('Decryption').last()).toBeVisible();
    await expect(page.getByText('Contexts Matter')).toBeVisible();
  });

  test('should show output panel', async ({ page }) => {
    // Output panel should be visible with ready state
    await expect(page.getByRole('heading', { name: 'Output' })).toBeVisible();
    await expect(page.getByText('Ready to execute')).toBeVisible();
  });
});
