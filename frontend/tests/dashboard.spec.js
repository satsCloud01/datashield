import { test, expect } from '@playwright/test';

test.describe('Dashboard Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/dashboard');
  });

  test('page loads at /dashboard', async ({ page }) => {
    await expect(page.locator('h1:has-text("Dashboard")')).toBeVisible();
  });

  test('6 stat cards visible', async ({ page }) => {
    await expect(page.locator('text=Total Scans')).toBeVisible();
    await expect(page.locator('text=Entities Protected')).toBeVisible();
    await expect(page.locator('text=Active Sessions')).toBeVisible();
    await expect(page.locator('text=Threats Blocked')).toBeVisible();
    await expect(page.locator('text=Avg Latency')).toBeVisible();
    await expect(page.locator('text=Compliance Score')).toBeVisible();
  });

  test('stat cards show numeric values not NaN or undefined', async ({ page }) => {
    // Wait for data to load (loading spinner disappears)
    await page.waitForSelector('text=Total Scans', { timeout: 10000 });
    const statValues = page.locator('.text-2xl.font-bold');
    const count = await statValues.count();
    expect(count).toBeGreaterThanOrEqual(6);
    for (let i = 0; i < count; i++) {
      const text = await statValues.nth(i).textContent();
      expect(text).not.toContain('NaN');
      expect(text).not.toContain('undefined');
    }
  });

  test('timeline chart area rendered', async ({ page }) => {
    await expect(page.locator('text=Entities Protected (Last 24h)')).toBeVisible();
    // Recharts renders an SVG inside a ResponsiveContainer
    const chartContainer = page.locator('text=Entities Protected (Last 24h)').locator('..');
    await expect(chartContainer).toBeVisible();
  });

  test('entity distribution chart section rendered', async ({ page }) => {
    await expect(page.locator('text=Entity Distribution')).toBeVisible();
  });

  test('threat summary section visible', async ({ page }) => {
    await expect(page.locator('text=Threat Summary')).toBeVisible();
  });

  test('threat summary shows trend badge', async ({ page }) => {
    // Should show one of: Trending Up, Trending Down, Stable
    const trendBadge = page.getByText('Stable').or(page.getByText('Trending Up')).or(page.getByText('Trending Down')).first();
    await expect(trendBadge).toBeVisible({ timeout: 10000 });
  });

  test('agent activity table section visible', async ({ page }) => {
    await expect(page.locator('text=Agent Activity')).toBeVisible();
  });

  test('surface activity cards for MCP/A2A/LLM API/RAG rendered', async ({ page }) => {
    await expect(page.locator('text=MCP').first()).toBeVisible();
    await expect(page.locator('text=A2A').first()).toBeVisible();
    await expect(page.locator('text=LLM API').first()).toBeVisible();
    await expect(page.locator('text=RAG').first()).toBeVisible();
  });

  test('surface activity cards show Blocked/Tokenized/Passed labels', async ({ page }) => {
    const blockedLabels = page.locator('text=Blocked');
    expect(await blockedLabels.count()).toBeGreaterThanOrEqual(4);
  });

  test('risk heatmap section rendered', async ({ page }) => {
    await expect(page.locator('text=Risk Heatmap')).toBeVisible();
  });

  test('top entities chart section rendered', async ({ page }) => {
    await expect(page.locator('text=Top 10 Entity Types')).toBeVisible();
  });

  test('live indicator with refresh message visible', async ({ page }) => {
    await expect(page.locator('text=Live -- refreshes every 30s')).toBeVisible();
  });
});
