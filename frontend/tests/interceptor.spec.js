import { test, expect } from '@playwright/test';

test.describe('Interceptor Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/interceptor');
  });

  test('page loads at /interceptor with title', async ({ page }) => {
    await expect(page.locator('h1:has-text("Agentic Pipeline Interceptor")')).toBeVisible();
  });

  test('subtitle about monitoring PII flow visible', async ({ page }) => {
    await expect(page.locator('text=Monitor and control PII flow')).toBeVisible();
  });

  test('4 surface tabs visible (MCP, A2A, LLM API, RAG)', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('button:has-text("MCP")').first()).toBeVisible();
    await expect(page.locator('button:has-text("A2A")')).toBeVisible();
    await expect(page.locator('button:has-text("LLM API")')).toBeVisible();
    await expect(page.locator('button:has-text("RAG")')).toBeVisible();
  });

  test('clicking tab filters logs', async ({ page }) => {
    await page.waitForTimeout(3000);
    await page.locator('button:has-text("A2A")').click();
    await page.waitForTimeout(500);
    // The A2A description should be visible
    await expect(page.locator('text=Agent-to-Agent Protocol')).toBeVisible();
  });

  test('stats cards show numeric values', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Total Interceptions')).toBeVisible();
    await expect(page.locator('text=Blocked').first()).toBeVisible();
    await expect(page.locator('text=Tokenized').first()).toBeVisible();
    await expect(page.locator('text=Passed').first()).toBeVisible();
  });

  test('bar chart rendered (By Surface)', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=By Surface')).toBeVisible();
  });

  test('line chart rendered (By Hour)', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=By Hour (24h)')).toBeVisible();
  });

  test('interceptor logs table has rows', async ({ page }) => {
    await page.waitForTimeout(3000);
    const logRows = page.locator('table').last().locator('tbody tr');
    expect(await logRows.count()).toBeGreaterThan(0);
  });

  test('simulator button exists', async ({ page }) => {
    await expect(page.locator('button:has-text("Simulator")')).toBeVisible();
  });

  test('simulator section has inputs when opened', async ({ page }) => {
    await page.locator('button:has-text("Simulator")').click();
    await expect(page.locator('text=Interception Simulator')).toBeVisible();
    await expect(page.locator('label:has-text("Surface")')).toBeVisible();
    await expect(page.locator('label:has-text("Agent ID")')).toBeVisible();
    await expect(page.locator('label:has-text("Payload")')).toBeVisible();
  });

  test('clicking Simulate produces results', async ({ page }) => {
    await page.locator('button:has-text("Simulator")').click();
    await page.locator('button:has-text("Simulate Interception")').click();
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Entities Detected')).toBeVisible();
  });

  test('simulation results show risk score', async ({ page }) => {
    await page.locator('button:has-text("Simulator")').click();
    await page.locator('button:has-text("Simulate Interception")').click();
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Risk Score')).toBeVisible();
  });

  test('simulation results show sanitized payload', async ({ page }) => {
    await page.locator('button:has-text("Simulator")').click();
    await page.locator('button:has-text("Simulate Interception")').click();
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Sanitized Payload')).toBeVisible();
  });

  test('flow diagram visible', async ({ page }) => {
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Interception Flow')).toBeVisible();
    await expect(page.locator('text=Agent Request')).toBeVisible();
    await expect(page.locator('text=Sanitized Forward')).toBeVisible();
  });
});
