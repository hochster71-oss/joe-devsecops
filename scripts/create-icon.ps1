# J.O.E. DevSecOps Arsenal - Professional Icon Generator
# Creates black background with blue glowing "J.O.E." text
# Dark Wolf Solutions

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$IcoPath = "C:\Users\micha\JOE\joe-devsecops\joe-dark-wolf.ico"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  J.O.E. Icon Generator" -ForegroundColor Cyan
Write-Host "  Dark Wolf Solutions" -ForegroundColor DarkGray
Write-Host "========================================`n" -ForegroundColor Cyan

# Create the icon at 256x256 (high resolution)
$size = 256
$bitmap = New-Object System.Drawing.Bitmap($size, $size)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)

# High quality rendering
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
$graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
$graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit

# Fill with pure black background
$blackBrush = [System.Drawing.Brushes]::Black
$graphics.FillRectangle($blackBrush, 0, 0, $size, $size)

# Create blue glow color (J.O.E. blue)
$joeBlue = [System.Drawing.Color]::FromArgb(255, 59, 130, 246)
$glowBlue = [System.Drawing.Color]::FromArgb(100, 59, 130, 246)
$lightBlue = [System.Drawing.Color]::FromArgb(255, 96, 165, 250)

# Draw outer glow circle
$glowPen = New-Object System.Drawing.Pen($glowBlue, 8)
$graphics.DrawEllipse($glowPen, 20, 20, $size - 40, $size - 40)

# Draw main circle border
$bluePen = New-Object System.Drawing.Pen($joeBlue, 4)
$graphics.DrawEllipse($bluePen, 30, 30, $size - 60, $size - 60)

# Create font for J.O.E. text
$fontFamily = New-Object System.Drawing.FontFamily("Segoe UI")
$fontSize = 56
$font = New-Object System.Drawing.Font($fontFamily, $fontSize, [System.Drawing.FontStyle]::Bold)

# Measure text to center it
$text = "J.O.E."
$textSize = $graphics.MeasureString($text, $font)
$textX = ($size - $textSize.Width) / 2
$textY = ($size - $textSize.Height) / 2 - 5

# Draw glow effect (multiple layers)
for ($i = 15; $i -ge 1; $i--) {
    $alpha = [int](30 - ($i * 1.5))
    if ($alpha -lt 5) { $alpha = 5 }
    $glowColor = [System.Drawing.Color]::FromArgb($alpha, 59, 130, 246)
    $glowBrush = New-Object System.Drawing.SolidBrush($glowColor)
    $graphics.DrawString($text, $font, $glowBrush, ($textX - $i/2), ($textY - $i/2))
    $graphics.DrawString($text, $font, $glowBrush, ($textX + $i/2), ($textY + $i/2))
    $glowBrush.Dispose()
}

# Draw main text with bright blue
$textBrush = New-Object System.Drawing.SolidBrush($lightBlue)
$graphics.DrawString($text, $font, $textBrush, $textX, $textY)

# Draw highlight/shine on text
$highlightBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(80, 255, 255, 255))
$highlightSize = $fontSize - 2
$highlightFont = New-Object System.Drawing.Font($fontFamily, $highlightSize, [System.Drawing.FontStyle]::Bold)
$graphics.DrawString($text, $highlightFont, $highlightBrush, ($textX + 1), ($textY - 1))

# Add small "DevSecOps" text below
$smallFont = New-Object System.Drawing.Font($fontFamily, 14, [System.Drawing.FontStyle]::Regular)
$smallText = "DevSecOps"
$smallSize = $graphics.MeasureString($smallText, $smallFont)
$smallX = ($size - $smallSize.Width) / 2
$smallY = $textY + $textSize.Height + 5
$dimBlueBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(180, 59, 130, 246))
$graphics.DrawString($smallText, $smallFont, $dimBlueBrush, $smallX, $smallY)

# Cleanup graphics resources
$graphics.Dispose()
$font.Dispose()
$highlightFont.Dispose()
$smallFont.Dispose()
$glowPen.Dispose()
$bluePen.Dispose()
$textBrush.Dispose()
$highlightBrush.Dispose()
$dimBlueBrush.Dispose()

Write-Host "[*] Creating icon at: $IcoPath" -ForegroundColor Yellow

# Convert bitmap to icon
$hIcon = $bitmap.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hIcon)

# Save icon
$fs = [System.IO.File]::Create($IcoPath)
$icon.Save($fs)
$fs.Close()

# Cleanup
$bitmap.Dispose()
$icon.Dispose()

Write-Host "[+] Icon created successfully!" -ForegroundColor Green

# Now recreate the desktop shortcut
Write-Host "`n[*] Creating desktop shortcut..." -ForegroundColor Yellow

$ShortcutPath = "$env:USERPROFILE\Desktop\J.O.E. DevSecOps Arsenal.lnk"
Remove-Item $ShortcutPath -Force -ErrorAction SilentlyContinue

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "C:\Users\micha\JOE\joe-devsecops\JOE-Dark-Wolf.bat"
$Shortcut.WorkingDirectory = "C:\Users\micha\JOE\joe-devsecops"
$Shortcut.Description = "J.O.E. DevSecOps Arsenal - Dark Wolf Security Platform"
$Shortcut.WindowStyle = 7  # Minimized
$Shortcut.IconLocation = "$IcoPath,0"
$Shortcut.Save()

Write-Host "[+] Desktop shortcut created!" -ForegroundColor Green

# Clear Windows icon cache to force refresh
Write-Host "`n[*] Refreshing Windows icon cache..." -ForegroundColor Yellow

# Method 1: Use ie4uinit
try {
    ie4uinit.exe -show 2>$null
} catch {}

# Method 2: Clear icon cache files
$iconCachePath = "$env:LOCALAPPDATA\IconCache.db"
if (Test-Path $iconCachePath) {
    Remove-Item $iconCachePath -Force -ErrorAction SilentlyContinue
}

# Method 3: Restart explorer to fully refresh
Write-Host "[*] Restarting Explorer to apply icon..." -ForegroundColor Yellow
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  Icon Installation Complete!" -ForegroundColor Green
Write-Host "  Check your desktop for the new icon" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Green
