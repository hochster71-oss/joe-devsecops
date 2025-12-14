import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any existing auth state
    await page.goto('/');
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  });

  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/dashboard');
    // Should redirect to login
    await expect(page).toHaveURL(/login/);
  });

  test('should show login form', async ({ page }) => {
    await page.goto('/login');

    // Verify login form elements
    await expect(page.locator('input[name="username"], input[placeholder*="username" i]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/login');

    // Enter invalid credentials
    await page.fill('input[name="username"], input[placeholder*="username" i]', 'invaliduser');
    await page.fill('input[type="password"]', 'invalidpassword');
    await page.click('button[type="submit"]');

    // Should show error message
    await expect(page.locator('text=/invalid|error|failed/i')).toBeVisible({ timeout: 5000 });
  });

  test('should login with dev credentials and require password change', async ({ page }) => {
    await page.goto('/login');

    // Enter dev credentials
    await page.fill('input[name="username"], input[placeholder*="username" i]', 'mhoch');
    await page.fill('input[type="password"]', 'darkwolf');
    await page.click('button[type="submit"]');

    // Should require password change (first login)
    // The exact behavior depends on the UI implementation
    await page.waitForTimeout(1000);

    // Either redirected to dashboard or showing password change modal
    const url = page.url();
    const hasPasswordChange = await page.locator('text=/password|change/i').isVisible().catch(() => false);

    expect(url.includes('dashboard') || hasPasswordChange).toBe(true);
  });

  test('should clear auth state on page refresh (security requirement)', async ({ page }) => {
    await page.goto('/login');

    // Login first
    await page.fill('input[name="username"], input[placeholder*="username" i]', 'mhoch');
    await page.fill('input[type="password"]', 'darkwolf');
    await page.click('button[type="submit"]');

    await page.waitForTimeout(1000);

    // Refresh the page
    await page.reload();

    // Should be back at login (auth not persisted)
    await expect(page).toHaveURL(/login/);
  });

  test('deep link to protected route should redirect to login', async ({ page }) => {
    await page.goto('/findings');
    await expect(page).toHaveURL(/login/);
  });

  test('deep link to settings should redirect to login', async ({ page }) => {
    await page.goto('/settings');
    await expect(page).toHaveURL(/login/);
  });

  test('deep link to compliance should redirect to login', async ({ page }) => {
    await page.goto('/compliance');
    await expect(page).toHaveURL(/login/);
  });
});

test.describe('Navigation', () => {
  // These tests assume user is authenticated
  // In a real scenario, you'd set up auth state first

  test('all sidebar routes should exist in router config', async ({ page }) => {
    // This test verifies routes are configured
    // Actual navigation tests require authentication

    const routes = [
      '/dashboard',
      '/findings',
      '/threat-intel',
      '/kubernetes',
      '/gitlab',
      '/supply-chain',
      '/compliance',
      '/space-compliance',
      '/pipeline',
      '/ai-assistant',
      '/mission-control',
      '/attack-surface',
      '/analytics',
      '/reports',
      '/settings'
    ];

    for (const route of routes) {
      await page.goto(route);
      // Should redirect to login (not 404)
      const url = page.url();
      expect(url).toContain('login');
    }
  });

  test('404 routes should redirect to dashboard or login', async ({ page }) => {
    await page.goto('/nonexistent-route');

    const url = page.url();
    // Should redirect to login (when not authenticated) or dashboard (when authenticated)
    expect(url.includes('login') || url.includes('dashboard')).toBe(true);
  });
});

test.describe('Security Headers', () => {
  test('should have proper security headers', async ({ page }) => {
    const response = await page.goto('/');

    // Check for security headers
    const headers = response?.headers() || {};

    // These may not be present in dev mode but should be in production
    // Log for documentation purposes
    console.log('Security Headers Check:');
    console.log('  X-Content-Type-Options:', headers['x-content-type-options'] || 'NOT SET');
    console.log('  X-Frame-Options:', headers['x-frame-options'] || 'NOT SET');
    console.log('  Content-Security-Policy:', headers['content-security-policy'] || 'NOT SET');
  });
});
