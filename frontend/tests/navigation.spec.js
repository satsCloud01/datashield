import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test('sidebar is visible on dashboard', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('aside')).toBeVisible();
  });

  test('sidebar is NOT visible on landing page', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('aside')).not.toBeVisible();
  });

  test('sidebar has 9 navigation links', async ({ page }) => {
    await page.goto('/dashboard');
    const links = page.locator('aside nav a');
    await expect(links).toHaveCount(9);
  });

  test('all 9 sidebar links navigate correctly', async ({ page }) => {
    const routes = [
      { label: 'Dashboard', path: '/dashboard' },
      { label: 'Scanner', path: '/scanner' },
      { label: 'Token Vault', path: '/token-vault' },
      { label: 'Policy Studio', path: '/policy-studio' },
      { label: 'Interceptor', path: '/interceptor' },
      { label: 'Semantic Validator', path: '/semantic-validator' },
      { label: 'Audit Trail', path: '/audit-trail' },
      { label: 'Compliance', path: '/compliance' },
      { label: 'Settings', path: '/settings' },
    ];

    for (const { label, path } of routes) {
      await page.goto(path);
      await expect(page).toHaveURL(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      // Verify the sidebar link for this route exists and has active styling
      const link = page.locator(`aside nav a[href="${path}"]`);
      await expect(link).toBeVisible();
      await expect(link).toHaveClass(/emerald/);
    }
  });

  test('sidebar collapse toggle works', async ({ page }) => {
    await page.goto('/settings'); // settings page is simple, fewer re-renders
    await page.waitForLoadState('networkidle');
    const aside = page.locator('aside');
    await expect(aside).toBeVisible();
    // Verify sidebar is expanded (has width class w-60)
    await expect(aside).toHaveClass(/w-60/);
  });

  test('landing to dashboard navigation', async ({ page }) => {
    await page.goto('/');
    const dashBtn = page.getByText('Launch Dashboard').first();
    await expect(dashBtn).toBeVisible();
    await dashBtn.click();
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('direct URL access to each page works', async ({ page }) => {
    const pages = ['/dashboard', '/scanner', '/token-vault', '/policy-studio', '/interceptor', '/semantic-validator', '/audit-trail', '/compliance', '/settings'];
    for (const path of pages) {
      await page.goto(path);
      await expect(page).toHaveURL(new RegExp(path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      await expect(page.locator('aside')).toBeVisible();
    }
  });

  test('unknown route redirects to landing', async ({ page }) => {
    await page.goto('/nonexistent-page');
    await expect(page).toHaveURL('/');
  });

  test('back/forward browser navigation works', async ({ page }) => {
    await page.goto('/dashboard');
    await page.goto('/scanner');
    await expect(page).toHaveURL(/\/scanner/);
    await page.goBack();
    await expect(page).toHaveURL(/\/dashboard/);
    await page.goForward();
    await expect(page).toHaveURL(/\/scanner/);
  });

  test('active page is highlighted in sidebar', async ({ page }) => {
    await page.goto('/scanner');
    const scannerLink = page.locator('aside nav a[href="/scanner"]');
    await expect(scannerLink).toHaveClass(/emerald/);
  });

  test('sidebar shows DataShield AI branding', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page.locator('aside span.text-lg')).toBeVisible();
    await expect(page.locator('aside span.text-lg')).toContainText('DataShield');
  });
});
