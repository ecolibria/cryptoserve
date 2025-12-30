import { test, expect } from '@playwright/test';
import { authenticateDevMode } from './fixtures';

test.describe('Compliance Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Authenticate first
    await authenticateDevMode(page);
    // Go to compliance page
    await page.goto('/admin/compliance');
    await page.waitForLoadState('networkidle');
  });

  test('should display compliance dashboard', async ({ page }) => {
    // Check page title in AdminLayout
    await expect(page.getByText('Compliance Dashboard').first()).toBeVisible();
  });

  test('should show compliance score circle', async ({ page }) => {
    // Look for the score visualization - "Overall Compliance" text
    await expect(page.getByText('Overall Compliance')).toBeVisible();

    // Check for the Score label under percentage (use exact match)
    await expect(page.getByText('Score', { exact: true })).toBeVisible();
  });

  test('should display KPI stat cards', async ({ page }) => {
    // Check for key metrics
    const metrics = ['Frameworks', 'Compliant', 'Partial', 'Non-Compliant', 'Open Issues', 'Avg Coverage'];

    for (const metric of metrics) {
      await expect(page.getByText(metric).first()).toBeVisible();
    }
  });

  test('should show compliance score trend chart', async ({ page }) => {
    // Look for trend chart section
    await expect(page.getByText('Compliance Score Trend')).toBeVisible();
  });

  test('should show coverage by framework chart', async ({ page }) => {
    // Look for coverage chart section
    await expect(page.getByText('Coverage by Framework')).toBeVisible();
  });

  test('should show issue summary', async ({ page }) => {
    // Look for issue summary section
    await expect(page.getByText('Issue Summary')).toBeVisible();
  });

  test('should show framework status grid', async ({ page }) => {
    // Look for framework status section heading
    await expect(page.getByRole('heading', { name: 'Framework Status' })).toBeVisible();
  });

  test('should show contexts compliance table', async ({ page }) => {
    // Look for contexts table
    await expect(page.getByText('Contexts by Compliance Coverage')).toBeVisible();
  });

  test('should have quick action cards', async ({ page }) => {
    // Scroll to bottom to see quick actions
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(300);

    // Check for quick action cards text
    await expect(page.getByText('Generate Audit Report')).toBeVisible();
    await expect(page.getByText('Review Open Issues')).toBeVisible();
    await expect(page.getByText('Set Compliance Goals')).toBeVisible();
  });

  test('should have export report button', async ({ page }) => {
    // Look for export button in header
    await expect(page.getByRole('button', { name: /Export Report/i })).toBeVisible();
  });

  test('should allow clicking on framework cards', async ({ page }) => {
    // Find a framework card button
    const frameworkCard = page.locator('button').filter({
      has: page.getByText(/SOC2|HIPAA|GDPR/i),
    }).first();

    // If frameworks are present, try clicking one
    if (await frameworkCard.isVisible()) {
      await frameworkCard.click();
      await page.waitForTimeout(300);

      // Should show requirements section after clicking
      await expect(page.getByText('Key Requirements')).toBeVisible();
      await expect(page.getByText('Linked Contexts')).toBeVisible();
    }
  });
});
