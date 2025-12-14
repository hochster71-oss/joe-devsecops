# Fix J.O.E. Desktop Shortcut with Dark Wolf Icon

$ShortcutPath = "$env:USERPROFILE\Desktop\J.O.E. Dark Wolf.lnk"
$IcoPath = "c:\Users\micha\JOE\joe-devsecops\resources\icons\joe-icon.ico"
$BatPath = "c:\Users\micha\JOE\joe-devsecops\JOE-Dark-Wolf.bat"

# Remove old shortcuts
Remove-Item "$env:USERPROFILE\Desktop\J.O.E Dark Wolf.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Desktop\J.O.E. Dark Wolf.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\Desktop\J.O.E. DevSecOps Arsenal.lnk" -Force -ErrorAction SilentlyContinue

# Create new shortcut with proper icon
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $BatPath
$Shortcut.WorkingDirectory = "c:\Users\micha\JOE\joe-devsecops"
$Shortcut.Description = "J.O.E. DevSecOps Arsenal - Dark Wolf Security Platform"
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "$IcoPath,0"
$Shortcut.Save()

Write-Host "Desktop shortcut created with Dark Wolf icon!" -ForegroundColor Green
Write-Host "Icon: $IcoPath" -ForegroundColor Cyan

# Refresh icon cache
ie4uinit.exe -show 2>$null
