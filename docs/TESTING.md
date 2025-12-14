# J.O.E. DevSecOps Arsenal - Testing Guide

## Test Structure

```
test/
├── unit/              # Unit tests (pure functions, components)
├── integration/       # Integration tests (API, services)
└── e2e/              # End-to-end tests (Playwright)
```

## Running Tests

### All Tests
```bash
npm test
```

### Unit Tests Only
```bash
npm run test:unit
```

### Integration Tests Only
```bash
npm run test:integration
```

### E2E Tests
```bash
npm run test:e2e
```

### Watch Mode (Development)
```bash
npm run test:watch
```

### Coverage Report
```bash
npm run test:coverage
```

## Test Matrix

### Authentication Flows

| Test Case | Type | Priority |
|-----------|------|----------|
| Login with valid credentials | E2E | Critical |
| Login with invalid credentials | E2E | Critical |
| 2FA verification flow | E2E | Critical |
| Session timeout (15 min inactivity) | E2E | High |
| Token expiration (24 hours) | Integration | High |
| Account lockout (5 failed attempts) | Integration | Critical |
| Password change flow | E2E | High |
| Logout clears session | E2E | Critical |
| Auth state not persisted on restart | E2E | Critical |

### Dashboard Flows

| Test Case | Type | Priority |
|-----------|------|----------|
| Dashboard loads after login | E2E | Critical |
| Dashboard refresh (F5) returns to login | E2E | High |
| Deep link requires authentication | E2E | Critical |
| Navigation between views | E2E | High |
| Back/forward browser history | E2E | Medium |
| New tab requires authentication | E2E | High |

### Security Features

| Test Case | Type | Priority |
|-----------|------|----------|
| Security scan execution | Integration | High |
| SBOM generation | Integration | High |
| Secret scanning | Integration | High |
| Kubernetes audit | Integration | Medium |
| GitLab security scan | Integration | Medium |
| Threat intelligence queries | Integration | Medium |

### API Error Handling

| Test Case | Type | Priority |
|-----------|------|----------|
| 401 triggers logout | Integration | Critical |
| 403 shows access denied | Integration | High |
| 500 shows error message | Integration | High |
| Network offline handling | E2E | Medium |
| Slow API response handling | E2E | Medium |

### Navigation Integrity

| Test Case | Type | Priority |
|-----------|------|----------|
| All sidebar links resolve | E2E | High |
| No broken internal routes | E2E | High |
| Menu items lead to valid views | E2E | High |
| 404 handling for invalid routes | E2E | Medium |

## Writing Tests

### Unit Test Example

```typescript
// test/unit/authStore.test.ts
import { describe, it, expect, beforeEach } from 'vitest';

describe('AuthStore', () => {
  beforeEach(() => {
    // Reset state
  });

  it('should start with unauthenticated state', () => {
    // Test implementation
  });

  it('should clear auth state on app load', () => {
    // Test implementation
  });
});
```

### Integration Test Example

```typescript
// test/integration/securityScanner.test.ts
import { describe, it, expect } from 'vitest';
import { securityScanner } from '../../electron/security-scanner';

describe('Security Scanner', () => {
  it('should return findings for vulnerable code', async () => {
    // Test implementation
  });
});
```

### E2E Test Example

```typescript
// test/e2e/auth.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/dashboard');
    await expect(page).toHaveURL('/login');
  });

  test('should login with valid credentials', async ({ page }) => {
    await page.goto('/login');
    await page.fill('[name="username"]', 'mhoch');
    await page.fill('[name="password"]', 'darkwolf');
    await page.click('button[type="submit"]');
    // Password change required on first login
    await expect(page.locator('text=Password Change')).toBeVisible();
  });
});
```

## CI Integration

Tests run automatically on PR via GitHub Actions:

1. **Lint + Format Check** - Code style validation
2. **Type Check** - TypeScript compilation
3. **Unit Tests** - Fast, isolated tests
4. **Integration Tests** - Service/API tests
5. **E2E Tests** - Full user flow tests (headless)

## Coverage Requirements

| Metric | Target |
|--------|--------|
| Line Coverage | 70% |
| Branch Coverage | 60% |
| Function Coverage | 70% |

Critical paths (auth, security) should have 90%+ coverage.

## Security Testing

### SAST (Static Analysis)
```bash
npm run security:sast
```

### DAST (Dynamic Analysis)
```bash
npm run security:dast
```

### Dependency Audit
```bash
npm audit
```

## Known Test Behaviors

### Dashboard Reset to Login

**This is BY DESIGN** - The app intentionally clears auth state on every restart for DoD STIG compliance. Tests should verify:
1. Auth is NOT persisted between app restarts
2. Deep links redirect to login when unauthenticated
3. Refresh (F5) returns to login screen

This is security behavior, not a bug.
