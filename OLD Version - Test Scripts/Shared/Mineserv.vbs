Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run "ssh #IP"
WScript.Sleep 300
WshShell.SendKeys "#PASSWORD"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
WshShell.SendKeys "clear"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
Set WshShell = Nothing
