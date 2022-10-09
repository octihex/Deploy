Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run "ssh #IP -p #PORT"
WScript.Sleep 200
WshShell.SendKeys "#PASSWORD"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
WScript.Sleep 100
WshShell.SendKeys "clear"
WScript.Sleep 100
WshShell.SendKeys "{ENTER}"
Set WshShell = Nothing
