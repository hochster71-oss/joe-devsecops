# GitHub Branch Protection Setup

## Required Configuration for DoD Compliance

This document describes the required branch protection rules for the J.O.E. DevSecOps Arsenal repository. These rules ensure that broken behavior cannot ship to production.

## Branch Protection Rules (main branch)

Go to: **Settings → Branches → Add rule**

### Rule 1: Require Pull Request Before Merging

- [x] **Require a pull request before merging**
  - [x] Require approvals: `1` (minimum)
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [ ] Require review from Code Owners (optional)
  - [x] Require approval of the most recent reviewable push

### Rule 2: Require Status Checks

- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging

**Required Status Checks:**
| Check Name | Description |
|------------|-------------|
| `ci / gates` | Main CI pipeline - lint, typecheck, unit tests, E2E, audit |
| `DevSecOps Pipeline / Build & Typecheck` | TypeScript compilation |
| `DevSecOps Pipeline / Unit Tests` | Vitest unit tests |
| `DevSecOps Pipeline / E2E Tests` | Playwright E2E tests |

### Rule 3: Additional Protections

- [x] **Do not allow bypassing the above settings**
- [x] **Restrict who can push to matching branches** (optional but recommended)
- [ ] **Require signed commits** (optional, for high-security environments)
- [ ] **Require linear history** (optional)
- [x] **Include administrators** (recommended - no exceptions)

## How to Configure

### Step 1: Access Branch Protection Settings

1. Go to your GitHub repository
2. Click **Settings** (gear icon)
3. In the left sidebar, click **Branches**
4. Under "Branch protection rules", click **Add rule**

### Step 2: Configure Rule Pattern

- **Branch name pattern**: `main`
  - If you also use `master`, add a separate rule for it

### Step 3: Enable Required Checks

Check the following boxes:
```
☑ Require a pull request before merging
  ☑ Require approvals: 1
  ☑ Dismiss stale pull request approvals when new commits are pushed
  ☑ Require approval of the most recent reviewable push

☑ Require status checks to pass before merging
  ☑ Require branches to be up to date before merging

  Search for and add these status checks:
  - ci / gates
  - DevSecOps Pipeline / Build & Typecheck
  - DevSecOps Pipeline / Unit Tests

☑ Do not allow bypassing the above settings
☑ Include administrators
```

### Step 4: Save Rule

Click **Create** to save the branch protection rule.

## Runtime Flow After Configuration

```
Developer pushes code
       ↓
    CI runs
       ↓
Lint → Typecheck → Unit → TestID coverage → Playwright → Security
       ↓
   [PASS] → PR may merge
   [FAIL] → AutoFix triggers
              ↓
           Analyze → Patch → Verify → PR opened
              ↓
           Branch protection enforces final gate
```

## Hard Guarantees

With these protections enabled:

1. ✅ **A button cannot exist without an E2E assertion**
2. ✅ **A broken click cannot silently pass**
3. ✅ **An AI fix cannot weaken security or correctness**
4. ✅ **Evidence exists for every failure and every fix**
5. ✅ **There is no path where broken behavior ships**

## Bot Approvals (Optional)

If using the AutoFix agent, consider:

- **Require approval for PRs from bots**: Enable if you want human oversight on all AI-generated fixes
- **Allow specified actors to bypass**: Disable for maximum security

## Compliance Notes

These branch protection rules align with:

- **NIST SP 800-53 Rev. 5**: CM-3 (Configuration Change Control)
- **DoD STIG**: Application Development STIG requirements
- **CMMC Level 3**: Practice CA.L2-3.12.4 (System Security Plan)
- **FedRAMP**: Configuration Management controls

---

*J.O.E. DevSecOps Arsenal - Dark Wolf Solutions*
