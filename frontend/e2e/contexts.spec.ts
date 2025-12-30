import { test, expect } from '@playwright/test';
import { authenticateDevMode } from './fixtures';

test.describe('Context Management', () => {
  test.beforeEach(async ({ page }) => {
    // Authenticate first
    await authenticateDevMode(page);
    // Go to contexts page
    await page.goto('/admin/contexts');
    await page.waitForLoadState('networkidle');
  });

  test('should display contexts page with stats', async ({ page }) => {
    // Check page title
    await expect(page.getByText('Context Management').first()).toBeVisible();

    // Check for stat cards
    await expect(page.getByText('Total Contexts')).toBeVisible();
    await expect(page.getByText('Total Operations')).toBeVisible();
  });

  test('should show create context button', async ({ page }) => {
    const createButton = page.getByRole('button', { name: /Create Context/i });
    await expect(createButton).toBeVisible();
  });

  test('should open create context modal', async ({ page }) => {
    // Click create button
    const createButton = page.getByRole('button', { name: /Create Context/i });
    await createButton.click();

    // Wait for modal
    await page.waitForTimeout(300);

    // Check modal content
    await expect(page.getByText('Create New Context')).toBeVisible();
    await expect(page.getByText('Context ID')).toBeVisible();
    await expect(page.getByText('Display Name')).toBeVisible();
  });

  test('should display operations chart section', async ({ page }) => {
    // Look for chart section
    await expect(page.getByText('Operations by Context')).toBeVisible();
  });

  test('should display key rotation status', async ({ page }) => {
    // Look for key rotation section
    await expect(page.getByText('Key Rotation Status')).toBeVisible();
  });

  test('should show all contexts section', async ({ page }) => {
    // Check for contexts grid
    await expect(page.getByText('All Contexts')).toBeVisible();
  });

  test('should show context cards or empty state', async ({ page }) => {
    // Either empty state or context cards should be visible
    const emptyState = page.getByText('No contexts configured');
    const allContextsSection = page.getByText('All Contexts');

    // All Contexts section should be visible
    await expect(allContextsSection).toBeVisible();

    // Check if empty state or cards are present
    const hasEmptyState = await emptyState.isVisible();
    if (hasEmptyState) {
      // Should show create button in empty state
      await expect(page.getByRole('button', { name: /Create Your First Context/i })).toBeVisible();
    }
  });

  test('should allow closing create modal', async ({ page }) => {
    // Open modal
    const createButton = page.getByRole('button', { name: /Create Context/i });
    await createButton.click();
    await page.waitForTimeout(300);

    // Modal should be open
    await expect(page.getByText('Create New Context')).toBeVisible();

    // Close modal via Cancel button
    const cancelButton = page.getByRole('button', { name: /Cancel/i });
    await cancelButton.click();

    // Modal should be closed
    await page.waitForTimeout(300);
    await expect(page.getByText('Create New Context')).not.toBeVisible();
  });

  test('should navigate through wizard steps', async ({ page }) => {
    // Open modal
    const createButton = page.getByRole('button', { name: /Create Context/i });
    await createButton.click();
    await page.waitForTimeout(300);

    // Fill in basic info
    await page.getByLabel('Context ID').fill('test-context');
    await page.getByLabel('Display Name').fill('Test Context');

    // Click Next button
    const nextButton = page.getByRole('button', { name: /Next/i });
    await nextButton.click();
    await page.waitForTimeout(300);

    // Should be on Data Identity step
    await expect(page.getByText('Data Category')).toBeVisible();
  });
});
