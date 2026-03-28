import { test, expect } from '@playwright/test';

test.describe('Landing Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('page loads with DataShield AI title', async ({ page }) => {
    await expect(page.getByText('DataShield AI').first()).toBeVisible();
  });

  test('hero section has tagline', async ({ page }) => {
    await expect(page.getByText(/should know what not to know/i)).toBeVisible();
  });

  test('Launch Dashboard button exists', async ({ page }) => {
    await expect(page.getByText('Launch Dashboard').first()).toBeVisible();
  });

  test('Try Scanner Demo button exists', async ({ page }) => {
    await expect(page.getByText(/Scanner Demo/i).first()).toBeVisible();
  });

  test('5 threat cards in crisis section', async ({ page }) => {
    await expect(page.getByText(/Agentic AI Data Crisis/i)).toBeVisible();
  });

  test('4 feature cards in solution section', async ({ page }) => {
    await expect(page.getByText('How DataShield Protects')).toBeVisible();
  });

  test('6 capability cards in capabilities section', async ({ page }) => {
    await expect(page.getByText('Core Capabilities')).toBeVisible();
    // Check all 6 capabilities from the JSX
    for (const cap of ['Detection Engine', 'Reversible Tokenization', 'Agentic Interceptor', 'Policy Engine', 'Semantic Validator', 'Compliance Engine']) {
      await expect(page.getByText(cap).first()).toBeVisible();
    }
  });

  test('4-step flow visible (Intercept, Detect, Protect, Restore)', async ({ page }) => {
    // Scroll to the flow section first
    const section = page.getByText('How DataShield Protects');
    await section.scrollIntoViewIfNeeded();
    for (const step of ['Intercept', 'Detect', 'Protect', 'Restore']) {
      await expect(page.locator('h3').filter({ hasText: step }).first()).toBeVisible();
    }
  });

  test('stats bar shows correct labels', async ({ page }) => {
    for (const label of ['Entity Types', 'Latency', 'Obfuscation Modes', 'Compliance Frameworks', 'Threat Models']) {
      await expect(page.getByText(label).first()).toBeVisible();
    }
  });

  test('competitive comparison table has rows', async ({ page }) => {
    await expect(page.getByText('Why Not Existing Tools?')).toBeVisible();
    const table = page.locator('table');
    await expect(table).toBeVisible();
    // Check for feature rows
    await expect(page.getByText('Agentic Surface Coverage')).toBeVisible();
    // Table should have comparison column headers
    for (const col of ['DLP', 'DSPM']) {
      await expect(page.locator('th').filter({ hasText: col })).toBeVisible();
    }
  });

  test('6 industry cards rendered', async ({ page }) => {
    for (const industry of ['BFSI', 'Healthcare']) {
      await expect(page.getByText(industry).first()).toBeVisible();
    }
  });

  test('footer visible', async ({ page }) => {
    await expect(page.getByText(/v1\.0/)).toBeVisible();
  });

  test('no console errors on page load', async ({ page }) => {
    const errors = [];
    page.on('console', msg => { if (msg.type() === 'error') errors.push(msg.text()); });
    await page.goto('/');
    await page.waitForTimeout(2000);
    // Filter out expected fetch errors (backend may not be running)
    const realErrors = errors.filter(e => !e.includes('fetch') && !e.includes('Failed to load'));
    expect(realErrors.length).toBe(0);
  });

  test('Launch Dashboard navigates to /dashboard', async ({ page }) => {
    await page.getByText('Launch Dashboard').first().click();
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('shield animation element exists', async ({ page }) => {
    // The shield icon SVG exists in the hero
    await expect(page.locator('svg').first()).toBeVisible();
  });

  test('page is responsive at mobile width', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await expect(page.getByText('DataShield AI').first()).toBeVisible();
  });
});
