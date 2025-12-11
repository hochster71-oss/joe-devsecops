$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\J.O.E. DevSecOps Arsenal.lnk")
$Shortcut.TargetPath = "C:\Users\micha\JOE\joe-devsecops\scripts\start.bat"
$Shortcut.WorkingDirectory = "C:\Users\micha\JOE\joe-devsecops"
$Shortcut.Description = "J.O.E. DevSecOps Arsenal - Dark Wolf Solutions"
$Shortcut.WindowStyle = 7
$Shortcut.Save()
Write-Host "Shortcut created on Desktop!"
