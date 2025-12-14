# Create Wolf Icon with Dark Background
# Clean look with dark rounded square behind the wolf head

Add-Type -AssemblyName System.Drawing

$sourcePath = "c:\Users\micha\JOE\joe-devsecops\src\renderer\assets\dark-wolf-logo.png"
$icoPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.ico"
$pngPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.png"

Write-Host "Loading source image..." -ForegroundColor Cyan
$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)

# Extract just the wolf head (left portion, tighter crop)
$wolfWidth = [int]($sourceImage.Height * 0.9)  # Tighter crop
$cropRect = New-Object System.Drawing.Rectangle(0, 0, $wolfWidth, $sourceImage.Height)

$croppedBitmap = New-Object System.Drawing.Bitmap($wolfWidth, $sourceImage.Height)
$graphics = [System.Drawing.Graphics]::FromImage($croppedBitmap)
$graphics.DrawImage($sourceImage, 0, 0, $cropRect, [System.Drawing.GraphicsUnit]::Pixel)
$graphics.Dispose()

# Create square icon with dark background
$iconSize = 256
$iconBitmap = New-Object System.Drawing.Bitmap($iconSize, $iconSize)
$iconGraphics = [System.Drawing.Graphics]::FromImage($iconBitmap)
$iconGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$iconGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$iconGraphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality

# Fill with dark background (#1E1E1E - matches the app theme)
$darkColor = [System.Drawing.Color]::FromArgb(255, 30, 30, 30)
$iconGraphics.Clear($darkColor)

# Draw rounded rectangle background
$cornerRadius = 40
$bgBrush = New-Object System.Drawing.SolidBrush($darkColor)
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$rect = New-Object System.Drawing.Rectangle(0, 0, $iconSize, $iconSize)
$path.AddArc($rect.X, $rect.Y, $cornerRadius * 2, $cornerRadius * 2, 180, 90)
$path.AddArc($rect.Right - $cornerRadius * 2, $rect.Y, $cornerRadius * 2, $cornerRadius * 2, 270, 90)
$path.AddArc($rect.Right - $cornerRadius * 2, $rect.Bottom - $cornerRadius * 2, $cornerRadius * 2, $cornerRadius * 2, 0, 90)
$path.AddArc($rect.X, $rect.Bottom - $cornerRadius * 2, $cornerRadius * 2, $cornerRadius * 2, 90, 90)
$path.CloseFigure()
$iconGraphics.FillPath($bgBrush, $path)

# Add subtle border
$borderColor = [System.Drawing.Color]::FromArgb(255, 74, 74, 74)
$borderPen = New-Object System.Drawing.Pen($borderColor, 2)
$iconGraphics.DrawPath($borderPen, $path)

# Scale wolf to fit with padding
$padding = 20
$availableSize = $iconSize - ($padding * 2)
$scale = [Math]::Min($availableSize / $croppedBitmap.Width, $availableSize / $croppedBitmap.Height)
$newWidth = [int]($croppedBitmap.Width * $scale)
$newHeight = [int]($croppedBitmap.Height * $scale)
$x = [int](($iconSize - $newWidth) / 2)
$y = [int](($iconSize - $newHeight) / 2)

$iconGraphics.DrawImage($croppedBitmap, $x, $y, $newWidth, $newHeight)
$iconGraphics.Dispose()

# Save PNG
Write-Host "Saving PNG..." -ForegroundColor Cyan
$iconBitmap.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)

# Create ICO with multiple sizes
Write-Host "Creating ICO..." -ForegroundColor Cyan
$sizes = @(16, 32, 48, 64, 128, 256)
$iconStream = New-Object System.IO.MemoryStream
$iconWriter = New-Object System.IO.BinaryWriter($iconStream)

$iconWriter.Write([int16]0)
$iconWriter.Write([int16]1)
$iconWriter.Write([int16]$sizes.Count)

$headerSize = 6 + ($sizes.Count * 16)
$currentOffset = $headerSize
$imageDataList = @()

foreach ($size in $sizes) {
    $resizedBitmap = New-Object System.Drawing.Bitmap($size, $size)
    $resizedGraphics = [System.Drawing.Graphics]::FromImage($resizedBitmap)
    $resizedGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $resizedGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $resizedGraphics.Clear($darkColor)
    $resizedGraphics.DrawImage($iconBitmap, 0, 0, $size, $size)
    $resizedGraphics.Dispose()

    $pngStream = New-Object System.IO.MemoryStream
    $resizedBitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngData = $pngStream.ToArray()
    $pngStream.Dispose()
    $resizedBitmap.Dispose()

    $imageDataList += ,@{Size=$size; Data=$pngData}
}

foreach ($item in $imageDataList) {
    $size = $item.Size
    $data = $item.Data
    $iconWriter.Write([byte]$(if ($size -ge 256) { 0 } else { $size }))
    $iconWriter.Write([byte]$(if ($size -ge 256) { 0 } else { $size }))
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([int16]1)
    $iconWriter.Write([int16]32)
    $iconWriter.Write([int32]$data.Length)
    $iconWriter.Write([int32]$currentOffset)
    $currentOffset += $data.Length
}

foreach ($item in $imageDataList) {
    $iconWriter.Write($item.Data)
}

$iconWriter.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $iconStream.ToArray())

$iconWriter.Dispose()
$iconStream.Dispose()
$croppedBitmap.Dispose()
$iconBitmap.Dispose()
$sourceImage.Dispose()

Write-Host "Icon created!" -ForegroundColor Green

# Update desktop shortcut
$desktopPath = [Environment]::GetFolderPath("Desktop")
Get-ChildItem -Path $desktopPath -Filter "*J.O.E*" -ErrorAction SilentlyContinue | Remove-Item -Force

$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$desktopPath\J.O.E. DevSecOps.lnk")
$shortcut.TargetPath = "c:\Users\micha\JOE\joe-devsecops\out\J.O.E. DevSecOps Arsenal-win32-x64\joe-devsecops.exe"
$shortcut.WorkingDirectory = "c:\Users\micha\JOE\joe-devsecops"
$shortcut.IconLocation = $icoPath
$shortcut.Description = "J.O.E. DevSecOps Arsenal - Dark Wolf Solutions"
$shortcut.Save()

Write-Host "Desktop shortcut updated!" -ForegroundColor Green
