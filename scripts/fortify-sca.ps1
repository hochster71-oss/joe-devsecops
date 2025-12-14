# J.O.E. DevSecOps Arsenal - Fortify SCA Integration
# Static Code Analysis with Fortify

param(
    [string]$BuildId = (Get-Date -Format "yyyyMMdd-HHmmss"),
    [string]$OutputDir = "artifacts/fortify",
    [switch]$Upload = $false
)

$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "J.O.E. Fortify SCA Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check for Fortify installation
$sourceanalyzer = $null
$possiblePaths = @(
    "$env:FORTIFY_HOME\bin\sourceanalyzer.exe",
    "C:\Program Files\Fortify\Fortify_SCA\bin\sourceanalyzer.exe",
    "C:\Fortify\bin\sourceanalyzer.exe",
    "/opt/fortify/bin/sourceanalyzer"
)

foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $sourceanalyzer = $path
        break
    }
}

if (-not $sourceanalyzer) {
    Write-Host "Fortify SCA not found." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To use Fortify SCA:" -ForegroundColor Cyan
    Write-Host "  1. Install Fortify SCA from your organization's software portal" -ForegroundColor White
    Write-Host "  2. Set FORTIFY_HOME environment variable" -ForegroundColor White
    Write-Host "  3. Ensure license is configured" -ForegroundColor White
    Write-Host ""
    Write-Host "For CI/CD integration, see:" -ForegroundColor Cyan
    Write-Host "  https://www.microfocus.com/documentation/fortify-static-code-analyzer" -ForegroundColor White
    Write-Host ""

    # Generate placeholder report
    Write-Host "Generating placeholder configuration..." -ForegroundColor Yellow

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    # Create Fortify configuration file
    $fortifyConfig = @"
# Fortify SCA Configuration for J.O.E. DevSecOps Arsenal
# Place this file in your Fortify project or CI/CD pipeline

# Build ID format
build.id=joe-devsecops-${BuildId}

# Source paths to scan
source.paths=src,electron

# Exclude patterns
exclude.patterns=node_modules/**,dist/**,coverage/**,*.test.ts,*.spec.ts

# TypeScript/JavaScript settings
typescript.enable=true
javascript.enable=true

# Security rules
rules.enabled=true
rules.custom=security/fortify-rules.xml

# Output settings
output.format=fpr
output.dir=${OutputDir}

# SSC Upload settings (if using Fortify SSC)
# ssc.url=https://your-ssc-server.com/ssc
# ssc.token=${env:FORTIFY_SSC_TOKEN}
# ssc.application=J.O.E. DevSecOps Arsenal
# ssc.version=1.0.0
"@

    Set-Content -Path "$OutputDir/fortify.properties" -Value $fortifyConfig

    # Create example CI/CD script
    $ciScript = @"
# Fortify SCA CI/CD Integration
# Add to your GitHub Actions or Jenkins pipeline

# GitHub Actions example:
# - name: Fortify SCA Scan
#   env:
#     FORTIFY_HOME: \${{ secrets.FORTIFY_HOME }}
#   run: |
#     \$FORTIFY_HOME/bin/sourceanalyzer -b joe-build -clean
#     \$FORTIFY_HOME/bin/sourceanalyzer -b joe-build src electron
#     \$FORTIFY_HOME/bin/sourceanalyzer -b joe-build -scan -f artifacts/fortify/joe.fpr

# Jenkins example:
# stage('Fortify Scan') {
#     steps {
#         fortifyScan buildID: 'joe-build',
#             resultsFile: 'artifacts/fortify/joe.fpr',
#             logFile: 'artifacts/fortify/joe.log'
#     }
# }

# Manual execution:
# 1. Clean: sourceanalyzer -b joe-build -clean
# 2. Translate: sourceanalyzer -b joe-build src electron
# 3. Scan: sourceanalyzer -b joe-build -scan -f joe.fpr
# 4. Upload: fortifyclient -url https://ssc.example.com -authtoken TOKEN uploadFPR -file joe.fpr -application "J.O.E." -applicationVersion "1.0"
"@

    Set-Content -Path "$OutputDir/fortify-ci-example.txt" -Value $ciScript

    Write-Host ""
    Write-Host "Created Fortify configuration files:" -ForegroundColor Green
    Write-Host "  - $OutputDir/fortify.properties" -ForegroundColor White
    Write-Host "  - $OutputDir/fortify-ci-example.txt" -ForegroundColor White
    Write-Host ""
    exit 0
}

# Fortify is installed - run the scan
Write-Host "Using Fortify at: $sourceanalyzer" -ForegroundColor Green
Write-Host "Build ID: $BuildId" -ForegroundColor Yellow
Write-Host ""

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Step 1: Clean
Write-Host "[1/3] Cleaning previous build..." -ForegroundColor Cyan
& $sourceanalyzer -b "joe-$BuildId" -clean

# Step 2: Translate (build)
Write-Host "[2/3] Translating source code..." -ForegroundColor Cyan
& $sourceanalyzer -b "joe-$BuildId" `
    -exclude "node_modules" `
    -exclude "dist" `
    -exclude "coverage" `
    -exclude "**/*.test.ts" `
    -exclude "**/*.spec.ts" `
    src electron

# Step 3: Scan
Write-Host "[3/3] Running security scan..." -ForegroundColor Cyan
& $sourceanalyzer -b "joe-$BuildId" `
    -scan `
    -f "$OutputDir/joe-$BuildId.fpr"

# Check results
if (Test-Path "$OutputDir/joe-$BuildId.fpr") {
    Write-Host ""
    Write-Host "Fortify scan complete!" -ForegroundColor Green
    Write-Host "FPR file: $OutputDir/joe-$BuildId.fpr" -ForegroundColor Cyan

    # Optional: Upload to SSC
    if ($Upload) {
        Write-Host ""
        Write-Host "Uploading to Fortify SSC..." -ForegroundColor Yellow
        # fortifyclient would be called here
        Write-Host "Note: Set SSC URL and token in environment variables" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "Scan may have failed. Check logs for details." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
