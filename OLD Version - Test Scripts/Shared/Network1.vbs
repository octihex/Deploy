Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run "ssh #IP"
WScript.Sleep 800
WshShell.SendKeys "#PASSWORD"
WScript.Sleep 10
WshShell.SendKeys "{ENTER}"
WScript.Sleep 10
WshShell.SendKeys "clear"
WScript.Sleep 10
WshShell.SendKeys "{ENTER}"
Set WshShell = Nothing
