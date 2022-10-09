@echo off
echo *** Installation LANDesk ***
set DebugCounterLANDesk=0
::msiexec /i C:\UEM\LANDesk.msi
call C:\UEM\LANDeskInfo.exe
shutdown -r -t 5
cd C:\
C:\UEM\Clean.lnk