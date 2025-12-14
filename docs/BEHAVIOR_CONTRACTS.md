# J.O.E. DevSecOps Arsenal - Behavior Contracts

## Overview

This document defines the **Behavior Contracts** for the J.O.E. DevSecOps Arsenal application.
These contracts specify the expected behavior of critical application features and MUST be
preserved across all code changes. Any modification that breaks these contracts requires
explicit approval and documentation.

**Compliance:** DoD Enterprise DevSecOps Reference Design v2.0, NIST SP 800-53 Rev. 5

---

## Authentication Contracts

### AUTH-001: Login Flow
```
GIVEN a user with valid credentials
WHEN they submit the login form
THEN the system shall:
  - Hash the password with bcrypt (cost factor 10+)
  - Compare against stored hash
  - Generate a session token (JWT)
  - Log the authentication event to audit log
  - Return user object (excluding password hash)
```

### AUTH-002: Session Timeout
```
GIVEN an authenticated user session
WHEN 15 minutes of inactivity has elapsed
THEN the system shall:
  - Automatically terminate the session
  - Require re-authentication
  - Log the timeout event

COMPLIANCE: DoD STIG requirement for session management
```

### AUTH-003: Failed Login Lockout
```
GIVEN a user attempting to login
WHEN 5 consecutive failed attempts occur
THEN the system shall:
  - Lock the account for 30 minutes
  - Log the lockout event with CRITICAL severity
  - Display lockout message to user

COMPLIANCE: NIST AC-7, DoD STIG
```

### AUTH-004: Password Requirements
```
GIVEN a user setting or changing their password
THEN the password MUST:
  - Be at least 15 characters (DoD privileged account requirement)
  - Contain uppercase, lowercase, numbers, and special characters
  - Not match any of the last 24 passwords
  - Expire after 30 days

COMPLIANCE: DoD STIG, NIST IA-5
```

---

## Two-Factor Authentication Contracts

### 2FA-001: Setup Flow
```
GIVEN an authenticated user enabling 2FA
WHEN they request 2FA setup
THEN the system shall:
  - Generate a TOTP secret
  - Create a QR code for authenticator apps
  - Store secret only after successful code verification
  - NOT enable 2FA until confirmation code is validated
```

### 2FA-002: Verification
```
GIVEN a user with 2FA enabled
WHEN they login with correct password
THEN the system shall:
  - Prompt for TOTP code
  - Validate code against stored secret
  - Allow 1 code time window tolerance
  - Log verification result
```

---

## IPC Security Contracts

### IPC-001: Context Isolation
```
GIVEN the Electron application
THEN:
  - contextIsolation MUST be enabled
  - nodeIntegration MUST be disabled
  - All renderer-to-main communication MUST use ipcRenderer.invoke
  - No Node.js APIs exposed directly to renderer
```

### IPC-002: Channel Validation
```
GIVEN an IPC handler in main process
WHEN receiving a message
THEN the handler MUST:
  - Validate all input parameters
  - Sanitize any user-provided strings
  - Return structured responses (not raw errors)
  - Not expose internal error details
```

---

## Data Security Contracts

### DATA-001: Sensitive Data Storage
```
GIVEN sensitive data (API keys, tokens, credentials)
THEN the system shall:
  - Store in SecureVault with AES-256 encryption
  - Never log sensitive values
  - Never store in plain text
  - Require master password for vault access
```

### DATA-002: Database Operations
```
GIVEN any database query
THEN:
  - All queries MUST use parameterized statements
  - No string concatenation for SQL construction
  - Results MUST be validated before use
```

---

## Export Contracts

### EXPORT-001: File Save
```
GIVEN a user exporting data
WHEN they initiate an export
THEN the system shall:
  - Use Electron's dialog.showSaveDialog
  - Not allow arbitrary file paths from renderer
  - Validate file extension matches export type
  - Log export event with file path
```

### EXPORT-002: PDF Generation
```
GIVEN a PDF export request
THEN the system shall:
  - Generate PDF server-side (main process)
  - Not execute any user content as code
  - Include generation timestamp and user in metadata
```

---

## Kubernetes Contracts

### K8S-001: Cluster Connection
```
GIVEN a Kubernetes cluster connection request
THEN the system shall:
  - Validate kubeconfig file exists
  - Test connection before marking as connected
  - Store connection state in kubernetesStore
  - Log connection/disconnection events
```

### K8S-002: Security Scanning
```
GIVEN a K8s security scan request
THEN the system shall:
  - Require active cluster connection
  - Scan for common misconfigurations
  - Check RBAC permissions
  - Identify privileged containers
  - Generate compliance findings
```

---

## GitLab Contracts

### GITLAB-001: Authentication
```
GIVEN a GitLab connection request
WHEN user provides URL and token
THEN the system shall:
  - Validate URL format
  - Test API connection with token
  - Store token in SecureVault (not plain text)
  - Verify minimum required permissions
```

---

## UI Contracts

### UI-001: Protected Routes
```
GIVEN a protected route
WHEN an unauthenticated user attempts access
THEN the system shall:
  - Redirect to /login
  - Not render protected content
  - Preserve intended destination for post-login redirect
```

### UI-002: Admin Routes
```
GIVEN an admin-only route (/admin)
WHEN a non-administrator user attempts access
THEN the system shall:
  - Redirect to /dashboard
  - Log unauthorized access attempt
  - Not expose admin functionality
```

### UI-003: Password Change Modal
```
GIVEN a user with requirePasswordChange flag
WHEN they access any protected route
THEN the system shall:
  - Display PasswordChangeModal
  - Block all other interactions
  - Require successful password change to continue

COMPLIANCE: DoD password expiration requirement
```

---

## Testing Contracts

### TEST-001: data-testid Coverage
```
GIVEN any interactive UI element (button, input, form)
THEN it MUST have a data-testid attribute for E2E testing
```

### TEST-002: Critical Path Coverage
```
The following user journeys MUST have E2E tests:
  - Login flow (success and failure)
  - 2FA setup and verification
  - Password change
  - Security scan execution
  - Report export
```

---

## Audit Logging Contracts

### AUDIT-001: Event Logging
```
The following events MUST be logged with timestamp, user, and outcome:
  - Login attempts (success/failure)
  - Session creation/termination
  - Password changes
  - 2FA changes
  - Security scan executions
  - Export operations
  - Admin actions
  - K8s/GitLab connections
```

### AUDIT-002: Log Retention
```
GIVEN audit log entries
THEN:
  - Keep minimum 1000 entries in memory
  - Persist to database on configurable schedule
  - Support export for compliance reporting
```

---

## Compliance Mapping

| Contract | NIST 800-53 | DoD STIG | CWE |
|----------|-------------|----------|-----|
| AUTH-001 | IA-2 | V-222396 | CWE-287 |
| AUTH-002 | AC-12 | V-222410 | CWE-613 |
| AUTH-003 | AC-7 | V-222399 | CWE-307 |
| AUTH-004 | IA-5 | V-222391 | CWE-521 |
| IPC-001 | SC-3 | N/A | CWE-749 |
| DATA-001 | SC-28 | V-222553 | CWE-312 |
| DATA-002 | SI-10 | V-222609 | CWE-89 |

---

## Contract Verification

Run the following to verify contracts are not broken:

```bash
# Type safety
npm run typecheck

# Linting
npm run lint

# Unit tests
npm run test

# E2E tests (when available)
npm run test:e2e

# data-testid coverage
npx ts-node scripts/check-testid-coverage.ts
```

---

*Last Updated: 2025-12-14*
*Version: 1.0.0*
*Maintained by: Dark Wolf Solutions*
