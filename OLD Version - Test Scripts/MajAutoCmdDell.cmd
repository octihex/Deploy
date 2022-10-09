@echo off

control update

TITLE Running DELL Command Update...
REM Checks for updated DELL Drivers using DELL Command Update CLI

"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /configure -silent -autoSuspendBitLocker=enable -userConsent=disable
ping 127.0.0.1 -n 3 > nul
cls
"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /scan -outputLog=C:\dell\logs\scan.log
ping 127.0.0.1 -n 3 > nul
cls
"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /applyUpdates -reboot=disable -outputLog=C:\dell\logs\applyUpdates.log
pause