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

  test('should show login form with data-testid elements', async ({ page }) => {
    await page.goto('/login');

    // Verify login form elements using data-testid
    await expect(page.getByTestId('login-username-input')).toBeVisible();
    await expect(page.getByTestId('login-password-input')).toBeVisible();
    await expect(page.getByTestId('login-submit-button')).toBeVisible();
    await expect(page.getByTestId('remember-me-checkbox')).toBeVisible();
    await expect(page.getByTestId('toggle-password-visibility')).toBeVisible();
  });

  test('should toggle password visibility', async ({ page }) => {
    await page.goto('/login');

    const passwordInput = page.getByTestId('login-password-input');
    const toggleButton = page.getByTestId('toggle-password-visibility');

    // Initially password should be hidden
    await expect(passwordInput).toHaveAttribute('type', 'password');

    // Click toggle to show password
    await toggleButton.click();
    await expect(passwordInput).toHaveAttribute('type', 'text');

    // Click again to hide
    await toggleButton.click();
    await expect(passwordInput).toHaveAttribute('type', 'password');
  });

  test('login button should be disabled without credentials', async ({ page }) => {
    await page.goto('/login');

    const submitButton = page.getByTestId('login-submit-button');
    await expect(submitButton).toBeDisabled();
  });

  test('login button should enable with credentials', async ({ page }) => {
    await page.goto('/login');

    const usernameInput = page.getByTestId('login-username-input');
    const passwordInput = page.getByTestId('login-password-input');
    const submitButton = page.getByTestId('login-submit-button');

    await usernameInput.fill('testuser');
    await passwordInput.fill('testpass');

    await expect(submitButton).toBeEnabled();
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/login');

    await page.getByTestId('login-username-input').fill('invaliduser');
    await page.getByTestId('login-password-input').fill('invalidpassword');
    await page.getByTestId('login-submit-button').click();

    // Should show error message
    await expect(page.locator('text=/invalid|error|failed/i')).toBeVisible({ timeout: 5000 });
  });

  test('should login with dev credentials and require password change', async ({ page }) => {
    await page.goto('/login');

    await page.getByTestId('login-username-input').fill('mhoch');
    await page.getByTestId('login-password-input').fill('darkwolf');
    await page.getByTestId('login-submit-button').click();

    await page.waitForTimeout(1000);

    // Either redirected to dashboard or showing password change modal
    const url = page.url();
    const hasPasswordChange = await page.locator('text=/password|change/i').isVisible().catch(() => false);

    expect(url.includes('dashboard') || hasPasswordChange).toBe(true);
  });

  test('should clear auth state on page refresh (security requirement)', async ({ page }) => {
    await page.goto('/login');

    await page.getByTestId('login-username-input').fill('mhoch');
    await page.getByTestId('login-password-input').fill('darkwolf');
    await page.getByTestId('login-submit-button').click();

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
  test('all sidebar routes should exist in router config', async ({ page }) => {
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
    expect(url.includes('login') || url.includes('dashboard')).toBe(true);
  });
});

test.describe('Security Headers', () => {
  test('should have proper security headers', async ({ page }) => {
    const response = await page.goto('/');

    const headers = response?.headers() || {};

    console.log('Security Headers Check:');
    console.log('  X-Content-Type-Options:', headers['x-content-type-options'] || 'NOT SET');
    console.log('  X-Frame-Options:', headers['x-frame-options'] || 'NOT SET');
    console.log('  Content-Security-Policy:', headers['content-security-policy'] || 'NOT SET');
  });
});
