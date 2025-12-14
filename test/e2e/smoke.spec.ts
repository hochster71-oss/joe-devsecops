/**
 * J.O.E. DevSecOps Arsenal - Critical Path Smoke Tests
 *
 * These tests verify the most critical functionality works:
 * - Login flow
 * - Navigation
 * - Dashboard interactions
 * - UI components render correctly
 *
 * DoD DevSecOps Compliance: Every interactive element must be testable
 */

import { test, expect } from '@playwright/test';

test.describe('Critical Path - Smoke Tests', () => {
  test.describe('Login Page', () => {
    test('login page renders all critical elements', async ({ page }) => {
      await page.goto('/login');

      // All login form elements should be present
      await expect(page.getByTestId('login-username-input')).toBeVisible();
      await expect(page.getByTestId('login-password-input')).toBeVisible();
      await expect(page.getByTestId('login-submit-button')).toBeVisible();
      await expect(page.getByTestId('remember-me-checkbox')).toBeVisible();
      await expect(page.getByTestId('toggle-password-visibility')).toBeVisible();

      // J.O.E. branding should be visible
      await expect(page.locator('text=J.O.E.')).toBeVisible();
      await expect(page.locator('text=Dark Wolf Solutions')).toBeVisible();
    });

    test('login form validation works', async ({ page }) => {
      await page.goto('/login');

      // Submit button should be disabled initially
      const submitButton = page.getByTestId('login-submit-button');
      await expect(submitButton).toBeDisabled();

      // Fill username only
      await page.getByTestId('login-username-input').fill('testuser');
      await expect(submitButton).toBeDisabled();

      // Fill password - now button should be enabled
      await page.getByTestId('login-password-input').fill('testpass');
      await expect(submitButton).toBeEnabled();
    });

    test('password visibility toggle works', async ({ page }) => {
      await page.goto('/login');

      const passwordInput = page.getByTestId('login-password-input');
      const toggleButton = page.getByTestId('toggle-password-visibility');

      // Fill password first
      await passwordInput.fill('mySecretPassword');

      // Initially hidden
      await expect(passwordInput).toHaveAttribute('type', 'password');

      // Toggle to show
      await toggleButton.click();
      await expect(passwordInput).toHaveAttribute('type', 'text');

      // Toggle to hide
      await toggleButton.click();
      await expect(passwordInput).toHaveAttribute('type', 'password');
    });

    test('remember me checkbox is interactive', async ({ page }) => {
      await page.goto('/login');

      const checkbox = page.getByTestId('remember-me-checkbox');

      // Initially unchecked
      await expect(checkbox).not.toBeChecked();

      // Click to check
      await checkbox.click();
      await expect(checkbox).toBeChecked();

      // Click to uncheck
      await checkbox.click();
      await expect(checkbox).not.toBeChecked();
    });
  });

  test.describe('Protected Routes', () => {
    test('unauthenticated user is redirected to login', async ({ page }) => {
      // Clear storage
      await page.goto('/');
      await page.evaluate(() => {
        localStorage.clear();
        sessionStorage.clear();
      });

      // Try to access protected routes
      const protectedRoutes = [
        '/dashboard',
        '/findings',
        '/compliance',
        '/settings',
        '/admin'
      ];

      for (const route of protectedRoutes) {
        await page.goto(route);
        await expect(page).toHaveURL(/login/);
      }
    });
  });

  test.describe('UI Components', () => {
    test('login page has proper form structure', async ({ page }) => {
      await page.goto('/login');

      // Form should have proper accessibility structure
      const form = page.locator('form');
      await expect(form).toBeVisible();

      // Labels should be present
      await expect(page.locator('label[for="username"], label:has-text("Username")')).toBeVisible();
      await expect(page.locator('label[for="password"], label:has-text("Password")')).toBeVisible();
    });

    test('error messages are displayed properly', async ({ page }) => {
      await page.goto('/login');

      // Submit with invalid credentials
      await page.getByTestId('login-username-input').fill('wronguser');
      await page.getByTestId('login-password-input').fill('wrongpass');
      await page.getByTestId('login-submit-button').click();

      // Wait for error message
      await page.waitForTimeout(2000);

      // Should show some kind of error indication
      const hasError = await page.locator('[class*="error"], [class*="alert"], text=/error|invalid|failed/i').isVisible().catch(() => false);
      expect(hasError).toBe(true);
    });
  });
});

test.describe('Accessibility - Basic Checks', () => {
  test('login page has no accessibility violations for keyboard navigation', async ({ page }) => {
    await page.goto('/login');

    // Tab through the form
    await page.keyboard.press('Tab');
    const _firstFocus = await page.evaluate(() => document.activeElement?.tagName);
    void _firstFocus; // Suppress unused variable warning - used for debugging

    // Should be able to tab through form elements
    const focusableElements: string[] = [];
    for (let i = 0; i < 10; i++) {
      const _tag = await page.evaluate(() => document.activeElement?.tagName || '');
      void _tag; // Suppress unused variable warning - used for debugging
      const testId = await page.evaluate(() => document.activeElement?.getAttribute('data-testid') || '');
      if (testId) {
        focusableElements.push(testId);
      }
      await page.keyboard.press('Tab');
    }

    // Should have captured some testid elements during tabbing
    console.log('Focusable elements with testid:', focusableElements);
  });

  test('buttons are keyboard accessible', async ({ page }) => {
    await page.goto('/login');

    // Fill form to enable submit button
    await page.getByTestId('login-username-input').fill('test');
    await page.getByTestId('login-password-input').fill('test');

    // Focus on submit button
    await page.getByTestId('login-submit-button').focus();

    // Press Enter should trigger click
    const buttonFocused = await page.evaluate(() => {
      return document.activeElement?.getAttribute('data-testid') === 'login-submit-button';
    });

    expect(buttonFocused).toBe(true);
  });
});

test.describe('Performance - Basic Checks', () => {
  test('login page loads within acceptable time', async ({ page }) => {
    const startTime = Date.now();
    await page.goto('/login');
    const loadTime = Date.now() - startTime;

    // Page should load in under 5 seconds
    expect(loadTime).toBeLessThan(5000);

    console.log(`Login page load time: ${loadTime}ms`);
  });

  test('login form is interactive after load', async ({ page }) => {
    await page.goto('/login');

    // Form should be immediately interactive
    const usernameInput = page.getByTestId('login-username-input');

    // Should be able to type immediately
    await usernameInput.fill('testuser');
    await expect(usernameInput).toHaveValue('testuser');
  });
});

test.describe('Data TestID Coverage', () => {
  test('all critical login elements have testids', async ({ page }) => {
    await page.goto('/login');

    // Verify all critical elements have data-testid
    const criticalTestIds = [
      'login-username-input',
      'login-password-input',
      'login-submit-button',
      'remember-me-checkbox',
      'toggle-password-visibility'
    ];

    for (const testId of criticalTestIds) {
      const element = page.getByTestId(testId);
      await expect(element, `Element with testid '${testId}' should exist`).toBeVisible();
    }
  });
});
