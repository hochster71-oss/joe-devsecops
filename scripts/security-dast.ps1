# J.O.E. DevSecOps Arsenal - DAST Scanning with OWASP ZAP
# Dynamic Application Security Testing

param(
    [string]$TargetUrl = "http://localhost:5173",
    [string]$OutputDir = "artifacts/zap",
    [switch]$FullScan = $false
)

$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "J.O.E. DAST Scanner (OWASP ZAP)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if ZAP is installed
$zapPath = $null
$possiblePaths = @(
    "C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
    "C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
    "$env:LOCALAPPDATA\OWASP ZAP\zap.bat",
    "/usr/share/zaproxy/zap.sh",
    "/opt/zaproxy/zap.sh"
)

foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $zapPath = $path
        break
    }
}

# Check for Docker ZAP
$hasDocker = $false
try {
    docker --version | Out-Null
    $hasDocker = $true
} catch {
    $hasDocker = $false
}

if (-not $zapPath -and -not $hasDocker) {
    Write-Host "OWASP ZAP not found. Please install ZAP or Docker." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Installation options:" -ForegroundColor Cyan
    Write-Host "  1. Download ZAP: https://www.zaproxy.org/download/" -ForegroundColor White
    Write-Host "  2. Use Docker: docker pull ghcr.io/zaproxy/zaproxy:stable" -ForegroundColor White
    Write-Host ""
    Write-Host "For CI/CD, add to GitHub Actions:" -ForegroundColor Cyan
    Write-Host '  - name: ZAP Scan'
    Write-Host '    uses: zaproxy/action-baseline@v0.12.0'
    Write-Host '    with:'
    Write-Host '      target: "${{ env.TARGET_URL }}"'
    Write-Host ""
    exit 1
}

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Target: $TargetUrl" -ForegroundColor Yellow
Write-Host "Output: $OutputDir" -ForegroundColor Yellow
Write-Host ""

if ($hasDocker) {
    Write-Host "Using Docker ZAP..." -ForegroundColor Cyan

    if ($FullScan) {
        Write-Host "Running FULL scan (this may take a while)..." -ForegroundColor Yellow
        docker run --rm -v "${PWD}/${OutputDir}:/zap/wrk:rw" `
            ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py `
            -t $TargetUrl `
            -r zap-report.html `
            -J zap-report.json `
            -w zap-report.md
    } else {
        Write-Host "Running BASELINE scan..." -ForegroundColor Yellow
        docker run --rm -v "${PWD}/${OutputDir}:/zap/wrk:rw" `
            ghcr.io/zaproxy/zaproxy:stable zap-baseline.py `
            -t $TargetUrl `
            -r zap-report.html `
            -J zap-report.json `
            -w zap-report.md
    }
} elseif ($zapPath) {
    Write-Host "Using local ZAP installation..." -ForegroundColor Cyan

    # Run ZAP in daemon mode and perform scan
    $zapArgs = @(
        "-daemon",
        "-quickurl", $TargetUrl,
        "-quickout", "$OutputDir/zap-report.html"
    )

    Start-Process -FilePath $zapPath -ArgumentList $zapArgs -Wait
}

# Check results
if (Test-Path "$OutputDir/zap-report.html") {
    Write-Host ""
    Write-Host "DAST scan complete!" -ForegroundColor Green
    Write-Host "Reports saved to: $OutputDir" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Files:" -ForegroundColor Yellow
    Get-ChildItem $OutputDir | ForEach-Object { Write-Host "  - $($_.Name)" }
} else {
    Write-Host ""
    Write-Host "Scan may have failed or produced no output." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
