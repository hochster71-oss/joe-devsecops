# J.O.E. DevSecOps Arsenal - Desktop Shortcut Creator
# Creates a desktop shortcut with Dark Wolf icon

# Delete existing shortcut
$ShortcutPath = "$env:USERPROFILE\Desktop\J.O.E. DevSecOps Arsenal.lnk"
if (Test-Path $ShortcutPath) {
    Remove-Item $ShortcutPath -Force
}

# Icon path
$IconPath = "C:\Users\micha\JOE\joe-devsecops\joe-dark-wolf.ico"

# Create shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "C:\Users\micha\JOE\joe-devsecops\JOE-Dark-Wolf.bat"
$Shortcut.WorkingDirectory = "C:\Users\micha\JOE\joe-devsecops"
$Shortcut.Description = "J.O.E. DevSecOps Arsenal - Dark Wolf Security"
$Shortcut.WindowStyle = 7
$Shortcut.IconLocation = "$IconPath,0"
$Shortcut.Save()

Write-Host "Shortcut created with Dark Wolf icon!"

# Refresh icon cache
Write-Host "Refreshing icon cache..."
ie4uinit.exe -show
