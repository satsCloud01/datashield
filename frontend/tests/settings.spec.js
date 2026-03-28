import { test, expect } from '@playwright/test';

test.describe('Settings Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/settings');
  });

  test('page loads at /settings with title', async ({ page }) => {
    await expect(page.locator('h1:has-text("Settings")')).toBeVisible();
  });

  test('vault TTL slider present', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Vault Configuration')).toBeVisible();
    await expect(page.locator('text=Vault TTL (seconds)')).toBeVisible();
    const slider = page.locator('input[type="range"]').first();
    await expect(slider).toBeVisible();
  });

  test('session timeout input present', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Session Timeout (seconds)')).toBeVisible();
    const input = page.locator('input[type="number"]').first();
    await expect(input).toBeVisible();
  });

  test('confidence threshold slider present', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Detection Configuration')).toBeVisible();
    await expect(page.locator('text=Confidence Threshold')).toBeVisible();
    const sliders = page.locator('input[type="range"]');
    expect(await sliders.count()).toBeGreaterThanOrEqual(2);
  });

  test('entity type toggles section rendered', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Enabled Entity Types')).toBeVisible();
  });

  test('agent roles table section visible', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Agent Roles')).toBeVisible();
    // Table with Role Name header
    await expect(page.locator('th:has-text("Role Name")')).toBeVisible();
  });

  test('Add Role form exists', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Add Role')).toBeVisible();
    await expect(page.locator('input[placeholder="Role name..."]')).toBeVisible();
    await expect(page.locator('button:has-text("Add Role")')).toBeVisible();
  });

  test('notification toggle switches present', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Notifications')).toBeVisible();
    await expect(page.locator('text=Email Notifications')).toBeVisible();
    await expect(page.locator('text=Slack Notifications')).toBeVisible();
    await expect(page.locator('text=SIEM Export')).toBeVisible();
    await expect(page.locator('text=Webhook')).toBeVisible();
  });

  test('Save Settings button exists', async ({ page }) => {
    await expect(page.locator('button:has-text("Save Settings")')).toBeVisible();
  });

  test('about section shows version info', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=About')).toBeVisible();
    await expect(page.locator('text=Version')).toBeVisible();
    await expect(page.locator('text=Engine')).toBeVisible();
    await expect(page.locator('text=DataShield AI')).toBeVisible();
  });
});
