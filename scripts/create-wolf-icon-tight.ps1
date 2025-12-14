# Create Wolf Icon - Tight Crop (Wolf Head Only)
Add-Type -AssemblyName System.Drawing

$sourcePath = "c:\Users\micha\JOE\joe-devsecops\src\renderer\assets\dark-wolf-logo.png"
$icoPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.ico"
$pngPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.png"

$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)

# Very tight crop - just the wolf head (about 30% of width)
$wolfWidth = [int]($sourceImage.Width * 0.22)
$cropRect = New-Object System.Drawing.Rectangle(0, 0, $wolfWidth, $sourceImage.Height)

$croppedBitmap = New-Object System.Drawing.Bitmap($wolfWidth, $sourceImage.Height)
$graphics = [System.Drawing.Graphics]::FromImage($croppedBitmap)
$graphics.DrawImage($sourceImage, 0, 0, $cropRect, [System.Drawing.GraphicsUnit]::Pixel)
$graphics.Dispose()

# Create icon with dark background
$iconSize = 256
$iconBitmap = New-Object System.Drawing.Bitmap($iconSize, $iconSize)
$iconGraphics = [System.Drawing.Graphics]::FromImage($iconBitmap)
$iconGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
$iconGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

# Dark background
$darkColor = [System.Drawing.Color]::FromArgb(255, 30, 30, 30)
$iconGraphics.Clear($darkColor)

# Rounded rectangle
$cornerRadius = 40
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$rect = New-Object System.Drawing.Rectangle(0, 0, $iconSize, $iconSize)
$path.AddArc($rect.X, $rect.Y, $cornerRadius * 2, $cornerRadius * 2, 180, 90)
$path.AddArc($rect.Right - $cornerRadius * 2, $rect.Y, $cornerRadius * 2, $cornerRadius * 2, 270, 90)
$path.AddArc($rect.Right - $cornerRadius * 2, $rect.Bottom - $cornerRadius * 2, $cornerRadius * 2, $cornerRadius * 2, 0, 90)
$path.AddArc($rect.X, $rect.Bottom - $cornerRadius * 2, $cornerRadius * 2, $cornerRadius * 2, 90, 90)
$path.CloseFigure()

$bgBrush = New-Object System.Drawing.SolidBrush($darkColor)
$iconGraphics.FillPath($bgBrush, $path)

$borderColor = [System.Drawing.Color]::FromArgb(255, 135, 197, 73)  # Green accent
$borderPen = New-Object System.Drawing.Pen($borderColor, 3)
$iconGraphics.DrawPath($borderPen, $path)

# Center the wolf with good padding
$padding = 25
$availableSize = $iconSize - ($padding * 2)
$scale = [Math]::Min($availableSize / $croppedBitmap.Width, $availableSize / $croppedBitmap.Height)
$newWidth = [int]($croppedBitmap.Width * $scale)
$newHeight = [int]($croppedBitmap.Height * $scale)
$x = [int](($iconSize - $newWidth) / 2)
$y = [int](($iconSize - $newHeight) / 2)

$iconGraphics.DrawImage($croppedBitmap, $x, $y, $newWidth, $newHeight)
$iconGraphics.Dispose()

# Save PNG
$iconBitmap.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)

# Create ICO
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
    $g = [System.Drawing.Graphics]::FromImage($resizedBitmap)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.Clear($darkColor)
    $g.DrawImage($iconBitmap, 0, 0, $size, $size)
    $g.Dispose()

    $ms = New-Object System.IO.MemoryStream
    $resizedBitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $imageDataList += ,@{Size=$size; Data=$ms.ToArray()}
    $ms.Dispose()
    $resizedBitmap.Dispose()
}

foreach ($item in $imageDataList) {
    $s = $item.Size
    $d = $item.Data
    $iconWriter.Write([byte]$(if ($s -ge 256) { 0 } else { $s }))
    $iconWriter.Write([byte]$(if ($s -ge 256) { 0 } else { $s }))
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([int16]1)
    $iconWriter.Write([int16]32)
    $iconWriter.Write([int32]$d.Length)
    $iconWriter.Write([int32]$currentOffset)
    $currentOffset += $d.Length
}

foreach ($item in $imageDataList) { $iconWriter.Write($item.Data) }
$iconWriter.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $iconStream.ToArray())

$iconWriter.Dispose()
$iconStream.Dispose()
$croppedBitmap.Dispose()
$iconBitmap.Dispose()
$sourceImage.Dispose()

# Update shortcut
$desktop = [Environment]::GetFolderPath("Desktop")
Get-ChildItem $desktop -Filter "*J.O.E*" -EA SilentlyContinue | Remove-Item -Force
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("$desktop\J.O.E. DevSecOps.lnk")
$sc.TargetPath = "c:\Users\micha\JOE\joe-devsecops\out\J.O.E. DevSecOps Arsenal-win32-x64\joe-devsecops.exe"
$sc.IconLocation = $icoPath
$sc.Save()

Write-Host "Done! Wolf icon with dark background and green border created." -ForegroundColor Green
