# Create proper Windows ICO file with multiple sizes
Add-Type -AssemblyName System.Drawing

$PngPath = "C:\Users\micha\JOE\joe-devsecops\src\renderer\assets\dark-wolf-logo.png"
$IcoPath = "C:\Users\micha\JOE\joe-devsecops\joe-dark-wolf.ico"

# Load source image
$sourceImage = [System.Drawing.Image]::FromFile($PngPath)

# Create icons at multiple sizes
$sizes = @(16, 32, 48, 64, 128, 256)
$icons = @()

foreach ($size in $sizes) {
    $bitmap = New-Object System.Drawing.Bitmap($size, $size)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.DrawImage($sourceImage, 0, 0, $size, $size)
    $graphics.Dispose()
    $icons += $bitmap
}

# Use the 256x256 version for the ICO
$largestBitmap = $icons[$icons.Count - 1]
$hIcon = $largestBitmap.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hIcon)

# Save to file
$fs = [System.IO.File]::Create($IcoPath)
$icon.Save($fs)
$fs.Close()

# Cleanup
foreach ($bmp in $icons) {
    $bmp.Dispose()
}
$sourceImage.Dispose()

Write-Host "Icon created: $IcoPath"

# Now recreate shortcut
$ShortcutPath = "$env:USERPROFILE\Desktop\J.O.E. DevSecOps Arsenal.lnk"
Remove-Item $ShortcutPath -Force -ErrorAction SilentlyContinue

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "C:\Users\micha\JOE\joe-devsecops\JOE-Dark-Wolf.bat"
$Shortcut.WorkingDirectory = "C:\Users\micha\JOE\joe-devsecops"
$Shortcut.Description = "J.O.E. DevSecOps Arsenal"
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "$IcoPath,0"
$Shortcut.Save()

Write-Host "Shortcut created!"

# Clear icon cache
$cacheDir = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer
Write-Host "Icon cache cleared - check your desktop!"
