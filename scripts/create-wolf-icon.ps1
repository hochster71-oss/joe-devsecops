# Create Wolf Icon from Dark Wolf Logo PNG
# Extracts just the wolf head for a clean app icon

Add-Type -AssemblyName System.Drawing

$sourcePath = "c:\Users\micha\JOE\joe-devsecops\src\renderer\assets\dark-wolf-logo.png"
$icoPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.ico"
$pngPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.png"

Write-Host "Loading source image..." -ForegroundColor Cyan
$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
Write-Host "  Source size: $($sourceImage.Width) x $($sourceImage.Height)"

# The wolf head is in the left portion of the image
# Calculate crop area for just the wolf head (roughly left 25% of the image)
$wolfWidth = [int]($sourceImage.Height * 1.2)  # Make it slightly wider than tall
$cropRect = New-Object System.Drawing.Rectangle(0, 0, $wolfWidth, $sourceImage.Height)

Write-Host "  Cropping wolf head area: $wolfWidth x $($sourceImage.Height)"

# Create cropped bitmap
$croppedBitmap = New-Object System.Drawing.Bitmap($wolfWidth, $sourceImage.Height)
$graphics = [System.Drawing.Graphics]::FromImage($croppedBitmap)
$graphics.DrawImage($sourceImage, 0, 0, $cropRect, [System.Drawing.GraphicsUnit]::Pixel)
$graphics.Dispose()

# Create square icon (256x256 for best quality)
$iconSize = 256
$iconBitmap = New-Object System.Drawing.Bitmap($iconSize, $iconSize)
$iconGraphics = [System.Drawing.Graphics]::FromImage($iconBitmap)
$iconGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$iconGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$iconGraphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

# Fill with transparent/dark background
$iconGraphics.Clear([System.Drawing.Color]::FromArgb(0, 0, 0, 0))

# Calculate scaling to fit wolf head in square, maintaining aspect ratio
$scale = [Math]::Min($iconSize / $croppedBitmap.Width, $iconSize / $croppedBitmap.Height)
$newWidth = [int]($croppedBitmap.Width * $scale)
$newHeight = [int]($croppedBitmap.Height * $scale)
$x = [int](($iconSize - $newWidth) / 2)
$y = [int](($iconSize - $newHeight) / 2)

$iconGraphics.DrawImage($croppedBitmap, $x, $y, $newWidth, $newHeight)
$iconGraphics.Dispose()

# Save as PNG first
Write-Host "Saving PNG icon..." -ForegroundColor Cyan
$iconBitmap.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "  Saved: $pngPath"

# Create ICO file with multiple sizes
Write-Host "Creating ICO file..." -ForegroundColor Cyan

# For ICO, we need to create multiple sizes
$sizes = @(16, 32, 48, 64, 128, 256)
$iconStream = New-Object System.IO.MemoryStream

# ICO Header
$iconWriter = New-Object System.IO.BinaryWriter($iconStream)
$iconWriter.Write([int16]0)        # Reserved
$iconWriter.Write([int16]1)        # Type (1 = ICO)
$iconWriter.Write([int16]$sizes.Count)  # Number of images

# Calculate offsets
$headerSize = 6 + ($sizes.Count * 16)  # Main header + directory entries
$currentOffset = $headerSize

$imageDataList = @()

foreach ($size in $sizes) {
    # Create resized bitmap
    $resizedBitmap = New-Object System.Drawing.Bitmap($size, $size)
    $resizedGraphics = [System.Drawing.Graphics]::FromImage($resizedBitmap)
    $resizedGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $resizedGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $resizedGraphics.Clear([System.Drawing.Color]::Transparent)
    $resizedGraphics.DrawImage($iconBitmap, 0, 0, $size, $size)
    $resizedGraphics.Dispose()

    # Save to memory stream as PNG
    $pngStream = New-Object System.IO.MemoryStream
    $resizedBitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngData = $pngStream.ToArray()
    $pngStream.Dispose()
    $resizedBitmap.Dispose()

    $imageDataList += ,@{Size=$size; Data=$pngData}
}

# Write directory entries
foreach ($item in $imageDataList) {
    $size = $item.Size
    $data = $item.Data

    $iconWriter.Write([byte]$(if ($size -ge 256) { 0 } else { $size }))  # Width
    $iconWriter.Write([byte]$(if ($size -ge 256) { 0 } else { $size }))  # Height
    $iconWriter.Write([byte]0)         # Color palette
    $iconWriter.Write([byte]0)         # Reserved
    $iconWriter.Write([int16]1)        # Color planes
    $iconWriter.Write([int16]32)       # Bits per pixel
    $iconWriter.Write([int32]$data.Length)  # Image data size
    $iconWriter.Write([int32]$currentOffset)  # Image data offset

    $currentOffset += $data.Length
}

# Write image data
foreach ($item in $imageDataList) {
    $iconWriter.Write($item.Data)
}

$iconWriter.Flush()

# Save ICO file
$iconBytes = $iconStream.ToArray()
[System.IO.File]::WriteAllBytes($icoPath, $iconBytes)

$iconWriter.Dispose()
$iconStream.Dispose()
$croppedBitmap.Dispose()
$iconBitmap.Dispose()
$sourceImage.Dispose()

Write-Host "  Saved: $icoPath" -ForegroundColor Green
Write-Host ""
Write-Host "Icon created successfully!" -ForegroundColor Green
Write-Host "Now creating desktop shortcut..." -ForegroundColor Cyan

# Delete old shortcuts
$desktopPath = [Environment]::GetFolderPath("Desktop")
Get-ChildItem -Path $desktopPath -Filter "*J.O.E*" -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -Path $desktopPath -Filter "*joe-devsecops*" -ErrorAction SilentlyContinue | Remove-Item -Force

# Create new shortcut
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$desktopPath\J.O.E. DevSecOps.lnk")
$shortcut.TargetPath = "c:\Users\micha\JOE\joe-devsecops\out\J.O.E. DevSecOps Arsenal-win32-x64\joe-devsecops.exe"
$shortcut.WorkingDirectory = "c:\Users\micha\JOE\joe-devsecops"
$shortcut.IconLocation = $icoPath
$shortcut.Description = "J.O.E. DevSecOps Arsenal - Dark Wolf Solutions"
$shortcut.Save()

Write-Host "Desktop shortcut created!" -ForegroundColor Green
