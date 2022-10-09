Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run "ssh #IP"
WScript.Sleep 200
WshShell.SendKeys "#PASSWORD"
WshShell.SendKeys "{ENTER}"
WScript.Sleep 10
WshShell.SendKeys "clear"
WshShell.SendKeys "{ENTER}"
Set WshShell = Nothing
