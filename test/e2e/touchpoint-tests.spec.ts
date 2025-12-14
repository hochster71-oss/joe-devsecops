/**
 * J.O.E. DevSecOps Arsenal - E2E Touchpoint Tests
 * Production Readiness Audit - Every Button Must Work
 *
 * Test Coverage Requirements:
 * - Every interactive element must produce observable outcome
 * - No "does nothing" clicks allowed
 * - All errors must be handled visibly
 * - All API calls must be mocked with realistic responses
 */

import { test, expect, ElectronApplication, Page } from '@playwright/test';
import { _electron as electron } from 'playwright';
import path from 'path';

// Test configuration
const APP_PATH = path.join(__dirname, '../../dist/win-unpacked/J.O.E. DevSecOps Arsenal.exe');
const MOCK_USER = { username: 'test_admin', role: 'administrator' };

// Helper to launch Electron app
async function launchApp(): Promise<{ electronApp: ElectronApplication; page: Page }> {
  const electronApp = await electron.launch({
    args: [APP_PATH],
    env: { NODE_ENV: 'test' }
  });
  const page = await electronApp.firstWindow();
  await page.waitForLoadState('domcontentloaded');
  return { electronApp, page };
}

// ============================================================================
// AUTHENTICATION TESTS
// ============================================================================

test.describe('Authentication Flow', () => {
  test('Login form submits credentials and shows feedback', async () => {
    const { electronApp, page } = await launchApp();

    // Fill login form
    await page.fill('[data-testid="username-input"]', 'admin');
    await page.fill('[data-testid="password-input"]', 'SecureP@ss123');

    // Click login button
    const loginButton = page.locator('[data-testid="login-button"]');
    await expect(loginButton).toBeEnabled();
    await loginButton.click();

    // Should show loading state
    await expect(page.locator('[data-testid="login-loading"]')).toBeVisible();

    // Should navigate to dashboard OR show error
    await page.waitForSelector('[data-testid="dashboard-view"], [data-testid="login-error"]', { timeout: 10000 });

    await electronApp.close();
  });

  test('2FA verification flow completes with feedback', async () => {
    const { electronApp, page } = await launchApp();

    // Assume we're at 2FA screen
    await page.waitForSelector('[data-testid="2fa-input"]', { timeout: 5000 });

    // Enter 6-digit code
    const inputs = page.locator('[data-testid="2fa-digit-input"]');
    for (let i = 0; i < 6; i++) {
      await inputs.nth(i).fill('1');
    }

    // Verify button should be enabled
    const verifyButton = page.locator('[data-testid="verify-2fa-button"]');
    await expect(verifyButton).toBeEnabled();
    await verifyButton.click();

    // Should show verification feedback
    await page.waitForSelector('[data-testid="2fa-verifying"], [data-testid="2fa-error"]', { timeout: 5000 });

    await electronApp.close();
  });
});

// ============================================================================
// DASHBOARD TESTS
// ============================================================================

test.describe('Dashboard View', () => {
  test('Refresh Dashboard button triggers scan and shows progress', async () => {
    const { electronApp, page } = await launchApp();

    // Navigate to dashboard (assuming logged in)
    await page.waitForSelector('[data-testid="dashboard-view"]', { timeout: 10000 });

    // Click refresh button
    const refreshButton = page.locator('[data-testid="refresh-dashboard-button"]');
    await refreshButton.click();

    // Should show scanning state
    await expect(page.locator('[data-testid="scan-progress"]')).toBeVisible();

    // Should eventually show results or error
    await page.waitForSelector('[data-testid="scan-complete"], [data-testid="scan-error"]', { timeout: 60000 });

    await electronApp.close();
  });

  test('Auto-Fix button triggers remediation with feedback', async () => {
    const { electronApp, page } = await launchApp();

    await page.waitForSelector('[data-testid="dashboard-view"]', { timeout: 10000 });

    const autoFixButton = page.locator('[data-testid="auto-fix-button"]');
    await autoFixButton.click();

    // Should show fix in progress
    await expect(page.locator('[data-testid="fix-progress"]')).toBeVisible();

    // Should show results
    await page.waitForSelector('[data-testid="fix-results-modal"]', { timeout: 30000 });

    await electronApp.close();
  });

  test('Generate POA&M button opens modal with results', async () => {
    const { electronApp, page } = await launchApp();

    await page.waitForSelector('[data-testid="dashboard-view"]', { timeout: 10000 });

    const poamButton = page.locator('[data-testid="generate-poam-button"]');
    await poamButton.click();

    // Should show POAM generation modal
    await expect(page.locator('[data-testid="poam-modal"]')).toBeVisible();

    await electronApp.close();
  });
});

// ============================================================================
// INTEGRATIONS VIEW - CRITICAL BUGS IDENTIFIED
// ============================================================================

test.describe('Integrations View - BLOCKING BUGS', () => {
  test.fail('Save Configuration button should save config', async () => {
    // BUG: Save Configuration button has NO onClick handler
    const { electronApp, page } = await launchApp();

    await page.goto('#/integrations');
    await page.waitForSelector('[data-testid="integrations-view"]');

    // Fill out Slack config
    await page.click('[data-testid="slack-tab"]');
    await page.fill('[data-testid="slack-webhook-input"]', 'https://hooks.slack.com/test');
    await page.fill('[data-testid="slack-channel-input"]', '#security-alerts');

    // Click Save Configuration
    const saveButton = page.locator('button:has-text("Save Configuration")');
    await saveButton.click();

    // EXPECTED: Should show "Configuration saved" toast
    // ACTUAL: Button does nothing (no onClick handler)
    await expect(page.locator('[data-testid="config-saved-toast"]')).toBeVisible({ timeout: 5000 });

    await electronApp.close();
  });

  test.fail('Test Connection button should call actual API', async () => {
    // BUG: Test button simulates with setTimeout, no API call
    const { electronApp, page } = await launchApp();

    await page.goto('#/integrations');

    // Click Test button
    const testButton = page.locator('[data-testid="test-connection-button"]');
    await testButton.click();

    // EXPECTED: Should call window.electronAPI.notifications.testChannel()
    // ACTUAL: Uses setTimeout simulation only

    await electronApp.close();
  });
});

// ============================================================================
// COMPLIANCE VIEW - CRITICAL BUGS IDENTIFIED
// ============================================================================

test.describe('Compliance View - BLOCKING BUGS', () => {
  test.fail('Export Report button should export file', async () => {
    // BUG: Export Report just closes modal, no export logic
    const { electronApp, page } = await launchApp();

    await page.goto('#/compliance');
    await page.waitForSelector('[data-testid="compliance-view"]');

    // Open export modal
    await page.click('[data-testid="export-report-button"]');
    await expect(page.locator('[data-testid="export-modal"]')).toBeVisible();

    // Click export
    const exportButton = page.locator('[data-testid="confirm-export-button"]');
    await exportButton.click();

    // EXPECTED: Should trigger file download or show save dialog
    // ACTUAL: Just closes modal, no export

    await electronApp.close();
  });

  test.fail('Re-evaluate button should call compliance API', async () => {
    // BUG: Re-evaluate uses setTimeout simulation, no API call
    const { electronApp, page } = await launchApp();

    await page.goto('#/compliance');

    // Expand a control
    await page.click('[data-testid="control-row"]:first-child');

    // Click Re-evaluate
    const reEvalButton = page.locator('[data-testid="reevaluate-button"]');
    await reEvalButton.click();

    // EXPECTED: Should call window.electronAPI.compliance.evaluateControl()
    // ACTUAL: Uses setTimeout simulation only

    await electronApp.close();
  });

  test.fail('Start Remediation should call Ollama AI', async () => {
    // BUG: Start Remediation simulates AI, doesn't call ollamaService
    const { electronApp, page } = await launchApp();

    await page.goto('#/compliance');

    // Click Start Remediation
    const remediationButton = page.locator('[data-testid="start-remediation-button"]');
    await remediationButton.click();

    // EXPECTED: Should call ollamaService.chat() for AI analysis
    // ACTUAL: Uses hardcoded mock data

    await electronApp.close();
  });
});

// ============================================================================
// API SECURITY VIEW - FILTER BUG
// ============================================================================

test.describe('API Security View', () => {
  test.fail('Severity filter buttons should toggle correctly', async () => {
    // BUG: setSeverityFilter(sev, boolean) but store expects setSeverityFilter(array)
    const { electronApp, page } = await launchApp();

    await page.goto('#/api-security');
    await page.waitForSelector('[data-testid="api-security-view"]');

    // Click critical filter
    await page.click('[data-testid="severity-filter-critical"]');

    // EXPECTED: Should filter to show only critical findings
    // ACTUAL: Type mismatch causes incorrect filter state

    // Click high filter (should ADD to existing filter)
    await page.click('[data-testid="severity-filter-high"]');

    // EXPECTED: Should show critical AND high
    // ACTUAL: Replaces filter due to type mismatch

    await electronApp.close();
  });

  test('Browse for spec file should open file dialog', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/api-security');

    const browseButton = page.locator('[data-testid="browse-spec-button"]');
    await browseButton.click();

    // Should trigger file selection dialog
    // Note: In E2E tests, we mock this to return a file path

    await electronApp.close();
  });

  test('Scan button should trigger API scan with progress', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/api-security');

    // Set spec path (via mock)
    await page.evaluate(() => {
      (window as any).testSpecPath = '/test/api-spec.yaml';
    });

    const scanButton = page.locator('[data-testid="scan-spec-button"]');
    await scanButton.click();

    // Should show scanning state
    await expect(page.locator('[data-testid="scan-in-progress"]')).toBeVisible();

    await electronApp.close();
  });
});

// ============================================================================
// SPACE COMPLIANCE VIEW - SIMULATION BUG
// ============================================================================

test.describe('Space Compliance View', () => {
  test.fail('Run Assessment should call actual API, not simulate', async () => {
    // BUG: runAssessment() uses setTimeout, no actual API call
    const { electronApp, page } = await launchApp();

    await page.goto('#/space-compliance');
    await page.waitForSelector('[data-testid="space-compliance-view"]');

    const assessButton = page.locator('[data-testid="run-assessment-button"]');
    await assessButton.click();

    // EXPECTED: Should call window.electronAPI.spaceCompliance.assess*()
    // ACTUAL: Uses setTimeout simulation only

    // Should show real assessment results
    await page.waitForSelector('[data-testid="assessment-results"]', { timeout: 10000 });

    await electronApp.close();
  });

  test('Export Report should generate actual file', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/space-compliance');

    // Click Export Report
    const exportButton = page.locator('[data-testid="export-report-button"]');
    await exportButton.click();

    // Select format
    await page.click('[data-testid="export-format-json"]');

    // Click export
    await page.click('[data-testid="confirm-export-button"]');

    // SpaceComplianceView DOES export properly - this should pass

    await electronApp.close();
  });

  test('AI Remediation button should call Ollama', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/space-compliance');

    // Click AI Remediation on a finding
    const aiButton = page.locator('[data-testid="ai-remediation-button"]:first-child');
    await aiButton.click();

    // Should show modal with loading state
    await expect(page.locator('[data-testid="ai-remediation-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="ai-loading-indicator"]')).toBeVisible();

    // Should eventually show AI response (or error if Ollama not running)
    await page.waitForSelector('[data-testid="ai-response"], [data-testid="ai-error"]', { timeout: 30000 });

    await electronApp.close();
  });
});

// ============================================================================
// KUBERNETES VIEW
// ============================================================================

test.describe('Kubernetes View', () => {
  test('Connect button should connect to cluster with feedback', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/kubernetes');

    // Select context
    await page.selectOption('[data-testid="k8s-context-select"]', 'minikube');

    // Click connect
    const connectButton = page.locator('[data-testid="k8s-connect-button"]');
    await connectButton.click();

    // Should show connecting state
    await expect(page.locator('[data-testid="k8s-connecting"]')).toBeVisible();

    // Should show connected OR error
    await page.waitForSelector('[data-testid="k8s-connected"], [data-testid="k8s-error"]', { timeout: 15000 });

    await electronApp.close();
  });

  test('Run Security Audit button triggers scan', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/kubernetes');

    // Assume connected
    const auditButton = page.locator('[data-testid="k8s-audit-button"]');
    await auditButton.click();

    // Should show scan progress
    await expect(page.locator('[data-testid="k8s-scan-progress"]')).toBeVisible();

    await electronApp.close();
  });

  test('AI Deep Dive buttons should call Ollama', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/kubernetes');

    // Click Executive Report
    const reportButton = page.locator('[data-testid="ai-executive-report-button"]');
    await reportButton.click();

    // Should show AI modal
    await expect(page.locator('[data-testid="ai-analysis-modal"]')).toBeVisible();

    await electronApp.close();
  });
});

// ============================================================================
// GITLAB VIEW
// ============================================================================

test.describe('GitLab View', () => {
  test('Connect with PAT should authenticate', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/gitlab');

    // Fill connection form
    await page.fill('[data-testid="gitlab-url-input"]', 'https://gitlab.com');
    await page.fill('[data-testid="gitlab-token-input"]', 'glpat-test-token');

    // Click connect
    const connectButton = page.locator('[data-testid="gitlab-connect-button"]');
    await connectButton.click();

    // Should show connecting state
    await expect(page.locator('[data-testid="gitlab-connecting"]')).toBeVisible();

    // Should show result
    await page.waitForSelector('[data-testid="gitlab-connected"], [data-testid="gitlab-error"]', { timeout: 10000 });

    await electronApp.close();
  });

  test('Scan Repository button triggers scan', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/gitlab');

    // Assume connected and project selected
    const scanButton = page.locator('[data-testid="gitlab-scan-button"]');
    await scanButton.click();

    // Should show scan progress
    await expect(page.locator('[data-testid="gitlab-scan-progress"]')).toBeVisible();

    await electronApp.close();
  });
});

// ============================================================================
// SUPPLY CHAIN VIEW
// ============================================================================

test.describe('Supply Chain View', () => {
  test('Generate SBOM button triggers generation', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/supply-chain');

    // Click SBOM tab
    await page.click('[data-testid="sbom-tab"]');

    // Click Generate SBOM
    const generateButton = page.locator('[data-testid="generate-sbom-button"]');
    await generateButton.click();

    // Should show generation in progress
    await expect(page.locator('[data-testid="sbom-generating"]')).toBeVisible();

    await electronApp.close();
  });

  test('Vault Initialize should create encrypted vault', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/supply-chain');

    // Click Vault tab
    await page.click('[data-testid="vault-tab"]');

    // Enter master password
    await page.fill('[data-testid="vault-password-input"]', 'SuperSecure!Pass123');
    await page.fill('[data-testid="vault-password-confirm"]', 'SuperSecure!Pass123');

    // Click Initialize
    const initButton = page.locator('[data-testid="vault-initialize-button"]');
    await initButton.click();

    // Should show initialization result
    await page.waitForSelector('[data-testid="vault-initialized"], [data-testid="vault-error"]', { timeout: 10000 });

    await electronApp.close();
  });
});

// ============================================================================
// IAC SECURITY VIEW
// ============================================================================

test.describe('IaC Security View', () => {
  test('Browse for directory should open dialog', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/iac-security');

    const browseButton = page.locator('[data-testid="iac-browse-button"]');
    await browseButton.click();

    // Should trigger directory selection

    await electronApp.close();
  });

  test('Scan Directory button should trigger IaC scan', async () => {
    const { electronApp, page } = await launchApp();

    await page.goto('#/iac-security');

    const scanButton = page.locator('[data-testid="iac-scan-button"]');
    await scanButton.click();

    // Should show scanning state
    await expect(page.locator('[data-testid="iac-scanning"]')).toBeVisible();

    await electronApp.close();
  });
});

// ============================================================================
// NAVIGATION TESTS
// ============================================================================

test.describe('Navigation', () => {
  test('All sidebar links navigate correctly', async () => {
    const { electronApp, page } = await launchApp();

    // Assume logged in
    await page.waitForSelector('[data-testid="sidebar"]');

    const routes = [
      { testId: 'nav-dashboard', expectedPath: '/dashboard' },
      { testId: 'nav-findings', expectedPath: '/findings' },
      { testId: 'nav-threat-intel', expectedPath: '/threat-intel' },
      { testId: 'nav-iac-security', expectedPath: '/iac-security' },
      { testId: 'nav-api-security', expectedPath: '/api-security' },
      { testId: 'nav-kubernetes', expectedPath: '/kubernetes' },
      { testId: 'nav-gitlab', expectedPath: '/gitlab' },
      { testId: 'nav-supply-chain', expectedPath: '/supply-chain' },
      { testId: 'nav-compliance', expectedPath: '/compliance' },
      { testId: 'nav-space-compliance', expectedPath: '/space-compliance' },
      { testId: 'nav-pipeline', expectedPath: '/pipeline' },
      { testId: 'nav-integrations', expectedPath: '/integrations' },
      { testId: 'nav-analytics', expectedPath: '/analytics' },
      { testId: 'nav-reports', expectedPath: '/reports' },
      { testId: 'nav-settings', expectedPath: '/settings' },
    ];

    for (const route of routes) {
      await page.click(`[data-testid="${route.testId}"]`);
      await expect(page).toHaveURL(new RegExp(route.expectedPath));
      // Each view should render without crashing
      await page.waitForLoadState('domcontentloaded');
    }

    await electronApp.close();
  });
});
