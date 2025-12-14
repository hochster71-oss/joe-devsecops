# Clear Windows Icon Cache Script
Write-Host "Clearing Windows icon cache..." -ForegroundColor Cyan

# Stop Explorer to release icon cache files
Write-Host "Stopping Explorer..."
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Delete icon cache files
$iconCachePath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
Write-Host "Deleting icon cache from: $iconCachePath"

Get-ChildItem -Path $iconCachePath -Filter "iconcache*" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "  Removing: $($_.Name)"
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -Path $iconCachePath -Filter "thumbcache*" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "  Removing: $($_.Name)"
    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
}

# Restart Explorer
Write-Host "Restarting Explorer..."
Start-Process explorer
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Icon cache cleared!" -ForegroundColor Green
Write-Host "If the old icon still shows, please restart your computer." -ForegroundColor Yellow
