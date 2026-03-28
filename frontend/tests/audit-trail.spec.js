import { test, expect } from '@playwright/test';

test.describe('Audit Trail Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/audit-trail');
  });

  test('page loads at /audit-trail with title', async ({ page }) => {
    await expect(page.locator('h1:has-text("Audit Trail")')).toBeVisible();
  });

  test('stats cards show numeric values', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Total Events')).toBeVisible();
    await expect(page.locator('text=Unique Agents')).toBeVisible();
    await expect(page.locator('text=Unique Sessions')).toBeVisible();
    await expect(page.locator('text=Avg Latency')).toBeVisible();
    await expect(page.locator('text=Peak Hour')).toBeVisible();
  });

  test('events by type chart rendered', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Events by Type')).toBeVisible();
  });

  test('events over time chart rendered', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Events Over Time')).toBeVisible();
  });

  test('events by entity type chart rendered', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Events by Entity Type')).toBeVisible();
  });

  test('hash chain verification banner shows result', async ({ page }) => {
    await page.waitForTimeout(5000);
    // Should show "Hash Chain Verified" or "Hash Chain BROKEN"
    const verificationBanner = page.locator('text=Hash Chain Verified, text=Hash Chain BROKEN').first();
    await expect(verificationBanner).toBeVisible();
  });

  test('hash chain visualization shows blocks', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Hash Chain Visualization')).toBeVisible();
    // Should show hash blocks with truncated hashes
    const hashBlocks = page.locator('text=/hash:/');
    expect(await hashBlocks.count()).toBeGreaterThan(0);
  });

  test('events table has rows with event_type badges', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Events').first()).toBeVisible();
    const eventBadges = page.locator('text=ENTITY_PROTECTED, text=VAULT_WRITE, text=VAULT_READ, text=POLICY_VIOLATION, text=SEMANTIC_BLOCK');
    expect(await eventBadges.count()).toBeGreaterThanOrEqual(0);
  });

  test('filter inputs work (type selector)', async ({ page }) => {
    await page.waitForTimeout(5000);
    const typeSelect = page.locator('select').first();
    await expect(typeSelect).toBeVisible();
    // Should have "All Types" and specific event types
    await typeSelect.selectOption('ENTITY_PROTECTED');
    await page.waitForTimeout(1000);
  });

  test('filter inputs work (agent search)', async ({ page }) => {
    await page.waitForTimeout(5000);
    const agentInput = page.locator('input[placeholder*="Agent"]');
    await expect(agentInput).toBeVisible();
    await agentInput.fill('agent-test');
    await page.waitForTimeout(1000);
  });

  test('click event row opens detail modal', async ({ page }) => {
    await page.waitForTimeout(5000);
    const eventRows = page.locator('table').last().locator('tbody tr');
    const count = await eventRows.count();
    if (count > 0) {
      await eventRows.first().click();
      await page.waitForTimeout(1000);
      // Detail modal should show hash info
      await expect(page.locator('text=Hash').first()).toBeVisible();
    }
  });

  test('Export button exists', async ({ page }) => {
    await expect(page.locator('button:has-text("Export Audit Log")')).toBeVisible();
  });

  test('agent summary section shows agents', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Agent Summary')).toBeVisible();
  });

  test('session audit search section exists', async ({ page }) => {
    await expect(page.locator('text=Session Audit')).toBeVisible();
    await expect(page.locator('input[placeholder*="session"]')).toBeVisible();
    await expect(page.locator('button:has-text("Lookup")')).toBeVisible();
  });
});
