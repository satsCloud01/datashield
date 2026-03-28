import { test, expect } from '@playwright/test';

test.describe('Policy Studio Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/policy-studio');
  });

  test('page loads at /policy-studio with title', async ({ page }) => {
    await expect(page.locator('h1:has-text("Policy Studio")')).toBeVisible();
  });

  test('subtitle about managing policies visible', async ({ page }) => {
    await expect(page.locator('text=Create, manage, and test data protection policies')).toBeVisible();
  });

  test('policy list sidebar shows policies', async ({ page }) => {
    // Wait for policies to load (either from API or fallback)
    await page.waitForTimeout(3000);
    // Should show at least one policy card
    const policyNames = page.locator('h3:has-text("BFSI"), h3:has-text("Healthcare"), h3:has-text("Strict"), h3:has-text("EU AI")');
    expect(await policyNames.count()).toBeGreaterThanOrEqual(1);
  });

  test('click policy shows detail view', async ({ page }) => {
    await page.waitForTimeout(3000);
    const firstPolicy = page.locator('[class*="cursor-pointer"]').first();
    await firstPolicy.click();
    await page.waitForTimeout(1000);
    // Should show YAML editor
    await expect(page.locator('text=Policy YAML')).toBeVisible();
  });

  test('YAML editor textarea is present with monospace font', async ({ page }) => {
    await page.waitForTimeout(3000);
    const firstPolicy = page.locator('[class*="cursor-pointer"]').first();
    await firstPolicy.click();
    const yamlTextarea = page.locator('textarea[spellcheck="false"]');
    await expect(yamlTextarea).toBeVisible();
    await expect(yamlTextarea).toHaveClass(/font-mono/);
  });

  test('compliance pack tags displayed on policy cards', async ({ page }) => {
    await page.waitForTimeout(3000);
    // Look for compliance pack badges like GDPR, HIPAA, PCI_DSS
    const packs = page.locator('text=GDPR, text=HIPAA, text=PCI_DSS, text=SOX').first();
    await expect(packs).toBeVisible();
  });

  test('Create Policy button exists', async ({ page }) => {
    await expect(page.locator('button:has-text("Create Policy")')).toBeVisible();
  });

  test('clicking Create Policy shows form', async ({ page }) => {
    await page.locator('button:has-text("+ Create Policy")').click();
    await expect(page.locator('text=Create New Policy')).toBeVisible();
    await expect(page.locator('text=Policy Name')).toBeVisible();
  });

  test('create policy form has template selector', async ({ page }) => {
    await page.locator('button:has-text("+ Create Policy")').click();
    await expect(page.locator('text=YAML Template')).toBeVisible();
    const select = page.locator('select').last();
    await expect(select).toBeVisible();
  });

  test('policy status badges visible (ACTIVE/DRAFT/ARCHIVED)', async ({ page }) => {
    await page.waitForTimeout(3000);
    // At least one status badge should be visible
    const badges = page.locator('text=ACTIVE, text=DRAFT, text=ARCHIVED');
    expect(await badges.count()).toBeGreaterThanOrEqual(1);
  });

  test('Test Policy button exists on selected policy', async ({ page }) => {
    await page.waitForTimeout(3000);
    const firstPolicy = page.locator('[class*="cursor-pointer"]').first();
    await firstPolicy.click();
    await expect(page.locator('button:has-text("Test Policy")')).toBeVisible();
  });

  test('validation indicator works', async ({ page }) => {
    await page.waitForTimeout(3000);
    const firstPolicy = page.locator('[class*="cursor-pointer"]').first();
    await firstPolicy.click();
    await page.locator('button:has-text("Validate")').click();
    await page.waitForTimeout(2000);
    // Should show Valid or Invalid indicator
    const indicator = page.locator('text=Valid, text=Invalid').first();
    await expect(indicator).toBeVisible();
  });
});
