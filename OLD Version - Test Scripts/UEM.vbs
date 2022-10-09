Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run "cmd.exe"
WScript.Sleep 100
WshShell.SendKeys "start /wait msiexec /i C:\UEM\LANDesk.msi"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
WScript.Sleep 5000
WshShell.SendKeys "^{Esc}"
WScript.Sleep 100
WshShell.SendKeys "{TAB}"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
WScript.Sleep 100
WshShell.SendKeys "{DOWN}"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
WScript.Sleep 100
WshShell.SendKeys "{UP}"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
Set WshShell = Nothing