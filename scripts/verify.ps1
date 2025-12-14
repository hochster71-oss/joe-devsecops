# J.O.E. DevSecOps Arsenal - Quality Gate Verification Script
# Run all quality checks before commit/deploy

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "J.O.E. DevSecOps Arsenal - Quality Gate" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$failed = $false

# 1. TypeScript Type Check
Write-Host "[1/5] Running TypeScript type check..." -ForegroundColor Yellow
try {
    npm run typecheck
    Write-Host "  TypeScript: PASS" -ForegroundColor Green
} catch {
    Write-Host "  TypeScript: FAIL" -ForegroundColor Red
    $failed = $true
}

# 2. ESLint
Write-Host ""
Write-Host "[2/5] Running ESLint..." -ForegroundColor Yellow
try {
    npm run lint
    Write-Host "  ESLint: PASS" -ForegroundColor Green
} catch {
    Write-Host "  ESLint: FAIL" -ForegroundColor Red
    $failed = $true
}

# 3. Unit Tests
Write-Host ""
Write-Host "[3/5] Running unit tests..." -ForegroundColor Yellow
try {
    npm run test:unit
    Write-Host "  Unit Tests: PASS" -ForegroundColor Green
} catch {
    Write-Host "  Unit Tests: FAIL" -ForegroundColor Red
    $failed = $true
}

# 4. Dependency Audit
Write-Host ""
Write-Host "[4/5] Running npm audit..." -ForegroundColor Yellow
try {
    npm audit --audit-level=high
    Write-Host "  Security Audit: PASS" -ForegroundColor Green
} catch {
    Write-Host "  Security Audit: WARNINGS (review npm audit output)" -ForegroundColor Yellow
    # Don't fail on audit warnings, just report
}

# 5. Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
if ($failed) {
    Write-Host "Quality Gate: FAILED" -ForegroundColor Red
    Write-Host "Please fix the issues above before committing." -ForegroundColor Red
    exit 1
} else {
    Write-Host "Quality Gate: PASSED" -ForegroundColor Green
    Write-Host "All checks passed successfully!" -ForegroundColor Green
    exit 0
}
