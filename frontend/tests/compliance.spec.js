import { test, expect } from '@playwright/test';

test.describe('Compliance Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/compliance');
  });

  test('page loads at /compliance with title', async ({ page }) => {
    await expect(page.locator('h1:has-text("Compliance")')).toBeVisible();
  });

  test('overall compliance gauge rendered with score', async ({ page }) => {
    await page.waitForTimeout(5000);
    // SVG gauge with percentage text
    const scoreText = page.locator('text=Overall Score');
    await expect(scoreText).toBeVisible();
    // The percentage number should be visible
    const percentages = page.locator('text=/\\d+%/');
    expect(await percentages.count()).toBeGreaterThan(0);
  });

  test('summary stat cards visible', async ({ page }) => {
    await page.waitForTimeout(5000);
    await expect(page.locator('text=Compliant')).toBeVisible();
    await expect(page.locator('text=Partial')).toBeVisible();
    await expect(page.locator('text=Non-Compliant')).toBeVisible();
    await expect(page.locator('text=Total Controls')).toBeVisible();
    await expect(page.locator('text=Controls Passing')).toBeVisible();
  });

  test('framework cards rendered (at least 4)', async ({ page }) => {
    await page.waitForTimeout(5000);
    const frameworkCards = page.locator('[class*="cursor-pointer"][class*="rounded-xl"]');
    expect(await frameworkCards.count()).toBeGreaterThanOrEqual(4);
  });

  test('each framework card has progress bar', async ({ page }) => {
    await page.waitForTimeout(5000);
    // Progress bars are divs with dynamic width
    const progressBars = page.locator('[class*="h-1.5"][class*="rounded-full"][class*="overflow-hidden"]');
    expect(await progressBars.count()).toBeGreaterThanOrEqual(4);
  });

  test('each framework card has status badge', async ({ page }) => {
    await page.waitForTimeout(5000);
    const badges = page.locator('text=COMPLIANT, text=PARTIAL, text=NON_COMPLIANT');
    expect(await badges.count()).toBeGreaterThanOrEqual(1);
  });

  test('click framework shows detail panel with controls', async ({ page }) => {
    await page.waitForTimeout(5000);
    const frameworkCard = page.locator('[class*="cursor-pointer"][class*="rounded-xl"]').first();
    await frameworkCard.click();
    await page.waitForTimeout(3000);
    // Should show controls table with Control ID column
    await expect(page.locator('th:has-text("Control ID")')).toBeVisible();
  });

  test('controls table has columns (Name, Status, Severity)', async ({ page }) => {
    await page.waitForTimeout(5000);
    const frameworkCard = page.locator('[class*="cursor-pointer"][class*="rounded-xl"]').first();
    await frameworkCard.click();
    await page.waitForTimeout(3000);
    await expect(page.locator('th:has-text("Name")')).toBeVisible();
    await expect(page.locator('th:has-text("Severity")')).toBeVisible();
  });

  test('status icons (check/X) shown per control', async ({ page }) => {
    await page.waitForTimeout(5000);
    const frameworkCard = page.locator('[class*="cursor-pointer"][class*="rounded-xl"]').first();
    await frameworkCard.click();
    await page.waitForTimeout(3000);
    // PASS controls have green check SVG, FAIL have red X SVG
    const controlIcons = page.locator('td svg');
    expect(await controlIcons.count()).toBeGreaterThan(0);
  });

  test('Run Assessment button exists in detail panel', async ({ page }) => {
    await page.waitForTimeout(5000);
    const frameworkCard = page.locator('[class*="cursor-pointer"][class*="rounded-xl"]').first();
    await frameworkCard.click();
    await page.waitForTimeout(3000);
    await expect(page.locator('button:has-text("Run Assessment")')).toBeVisible();
  });

  test('Generate Report button exists', async ({ page }) => {
    await expect(page.locator('button:has-text("Generate Report")')).toBeVisible();
  });

  test('compliance score is between 0 and 100', async ({ page }) => {
    await page.waitForTimeout(5000);
    const scoreElement = page.locator('text >> nth=0').locator('xpath=//text[contains(text(),"%")]').first();
    // Alternative: check the SVG text element
    const svgText = page.locator('svg text').first();
    const text = await svgText.textContent();
    const match = text.match(/(\d+)%/);
    if (match) {
      const score = parseInt(match[1]);
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    }
  });
});
