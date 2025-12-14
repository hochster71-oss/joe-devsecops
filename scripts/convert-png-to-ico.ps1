# Convert Dark Wolf PNG to proper ICO file with multiple resolutions

Add-Type -AssemblyName System.Drawing

$PngPath = "c:\Users\micha\JOE\joe-devsecops\src\renderer\assets\dark-wolf-logo.png"
$IcoPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.ico"

Write-Host "Converting Dark Wolf logo to ICO..." -ForegroundColor Cyan

# Load the source PNG
$sourceImage = [System.Drawing.Image]::FromFile($PngPath)

Write-Host "Source image size: $($sourceImage.Width)x$($sourceImage.Height)" -ForegroundColor Yellow

# Create a 256x256 bitmap (Windows icon standard)
$size = 256
$bitmap = New-Object System.Drawing.Bitmap($size, $size)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)

# High quality rendering
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

# Fill with transparent background
$graphics.Clear([System.Drawing.Color]::Transparent)

# Calculate scaling to fit the wolf logo (left portion of the image)
# The source image has wolf on left, "WOLF" text on right
# We want just the wolf head, which is roughly the left third
$wolfWidth = [int]($sourceImage.Width * 0.35)
$wolfHeight = $sourceImage.Height

# Calculate destination rectangle to center and fit
$scale = [Math]::Min($size / $wolfWidth, $size / $wolfHeight) * 0.9
$destWidth = [int]($wolfWidth * $scale)
$destHeight = [int]($wolfHeight * $scale)
$destX = ($size - $destWidth) / 2
$destY = ($size - $destHeight) / 2

# Draw the wolf portion of the source image
$srcRect = New-Object System.Drawing.Rectangle(0, 0, $wolfWidth, $wolfHeight)
$destRect = New-Object System.Drawing.Rectangle($destX, $destY, $destWidth, $destHeight)
$graphics.DrawImage($sourceImage, $destRect, $srcRect, [System.Drawing.GraphicsUnit]::Pixel)

$graphics.Dispose()

# Convert to icon and save
$hIcon = $bitmap.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hIcon)

$fs = [System.IO.File]::Create($IcoPath)
$icon.Save($fs)
$fs.Close()

# Cleanup
$sourceImage.Dispose()
$bitmap.Dispose()
$icon.Dispose()

Write-Host "ICO file created: $IcoPath" -ForegroundColor Green

# Also copy to root for the old shortcut location
Copy-Item $IcoPath "c:\Users\micha\JOE\joe-devsecops\joe-dark-wolf.ico" -Force
Write-Host "Also updated: joe-dark-wolf.ico" -ForegroundColor Green
