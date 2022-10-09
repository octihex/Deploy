@echo off
IF EXIST %userprofile%\Deploy.txt goto APP2
IF NOT EXIST %userprofile%\Deploy.txt goto APP1

:APP1
cd %userprofile%\Applications\
cd UEM
echo *** Installation LANDesk ***
start /wait msiexec /i FR-S602-Agent-Windows-Workstation.msi
cd ..
cls
cd Crowstricke
echo *** Installation Crowstricke ***
@WindowsSensor.LionLanner.exe /install /quiet /norestart CID=5738AB7D43BD43B69165AC612F534C4F-30
cd ..
cls
cd Citrix
echo *** Citrix Workspace app Installation ***
call CitrixWorkspaceApp_1912CU2.exe /noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false
cd ..
cls
cd Office
call C:\Windows\SysWOW64\Cscript.exe Office365.vbs ALL /Quiet /NoCancel /Force /OSE
call C:\Windows\SysWOW64\Cscript.exe Office15.vbs ALL /Quiet /NoCancel /Force /OSE
cd %userprofile%
echo g > Deploy.txt
pause
shutdown -r -t 00

:APP2
cd %userprofile%\Applications\Office\
call OfficeSetup.exe
call TeamsSetup.exe
cd ..
call 7zip.exe
call Adobe.exe
call Chrome.exe
cd Public
copy TeamViewerQS.exe C:\users\public\Desktop
copy "Microsoft Teams.lnk" C:\users\public\Desktop
del %userprofile%\Deploy.txt
cls
dir "C:\Program Files (x86)\LANDesk"
@sc query csagent
Pause
Clean.cmd
