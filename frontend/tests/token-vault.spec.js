import { test, expect } from '@playwright/test';

test.describe('Token Vault Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/token-vault');
  });

  test('page loads at /token-vault with title', async ({ page }) => {
    await expect(page.locator('h1:has-text("Token Vault")')).toBeVisible();
  });

  test('subtitle about reversible tokenization visible', async ({ page }) => {
    await expect(page.locator('text=Reversible tokenization')).toBeVisible();
  });

  test('original text textarea is pre-filled and editable', async ({ page }) => {
    const textarea = page.locator('textarea').first();
    const value = await textarea.inputValue();
    expect(value).toContain('John Smith');
    await textarea.fill('Test input data with SSN 999-88-7777');
    const newValue = await textarea.inputValue();
    expect(newValue).toContain('999-88-7777');
  });

  test('6 mode selector buttons visible', async ({ page }) => {
    await expect(page.locator('text=Protection Mode')).toBeVisible();
    for (const mode of ['Redact', 'Tokenize', 'Pseudonymize', 'Generalize', 'Encrypt', 'Synthesize']) {
      await expect(page.locator(`div:has-text("${mode}") >> text="${mode}"`).first()).toBeVisible();
    }
  });

  test('Protect button is clickable', async ({ page }) => {
    const protectBtn = page.locator('button:has-text("Protect")').first();
    await expect(protectBtn).toBeVisible();
    await expect(protectBtn).toBeEnabled();
  });

  test('after protect, protected text panel shows sanitized text', async ({ page }) => {
    await page.locator('button:has-text("Protect")').first().click();
    await page.waitForTimeout(3000);
    // Protected text area should show cyan-colored text
    const protectedPanel = page.locator('text=Protected Text').locator('..');
    await expect(protectedPanel).toBeVisible();
    const protectedSpan = page.locator('.text-cyan-300').first();
    await expect(protectedSpan).toBeVisible();
  });

  test('token mapping table appears with entries after protect', async ({ page }) => {
    await page.locator('button:has-text("Protect")').first().click();
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Token Mapping')).toBeVisible();
    const rows = page.locator('table').last().locator('tbody tr');
    expect(await rows.count()).toBeGreaterThan(0);
  });

  test('Restore button appears after protect', async ({ page }) => {
    await page.locator('button:has-text("Protect")').first().click();
    await page.waitForTimeout(3000);
    await expect(page.locator('button:has-text("Restore Original")')).toBeVisible();
  });

  test('restore shows original text', async ({ page }) => {
    await page.locator('button:has-text("Protect")').first().click();
    await page.waitForTimeout(3000);
    await page.locator('button:has-text("Restore Original")').click();
    await page.waitForTimeout(3000);
    await expect(page.locator('text=Restored Text')).toBeVisible();
  });

  test('fidelity badge shows 100% Fidelity on match', async ({ page }) => {
    await page.locator('button:has-text("Protect")').first().click();
    await page.waitForTimeout(3000);
    await page.locator('button:has-text("Restore Original")').click();
    await expect(page.locator('text=100% Fidelity')).toBeVisible({ timeout: 10000 });
  });

  test('session info panel shows session details or create option', async ({ page }) => {
    // Either shows "No active session" or session details
    const sessionPanel = page.locator('text=Session ID, text=No active session').first();
    await expect(sessionPanel).toBeVisible();
  });

  test('vault stats section visible', async ({ page }) => {
    await expect(page.locator('text=Vault Utilization')).toBeVisible();
  });

  test('mode switching changes output format', async ({ page }) => {
    // Click REDACT mode
    await page.locator('div:has-text("Redact")').first().click();
    await page.locator('button:has-text("Protect")').first().click();
    await page.waitForTimeout(3000);
    const protectedSpan = page.locator('.text-cyan-300').first();
    const text = await protectedSpan.textContent();
    expect(text).toContain('[REDACTED]');
  });
});
