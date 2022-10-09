@echo off
IF EXIST %userprofile%\Deploy.txt goto APP2
IF NOT EXIST %userprofile%\Deploy.txt goto APP1

:APP1
copy Deploy.lnk "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
cd %userprofile%\Applications\

echo *** Installation LANDesk ***
msiexec /i %userprofile%\Applications\UEM\FR-S602-Agent-Windows-Workstation.msi

cls

echo *** Installation Crowstricke ***
call Crowstricke\WindowsSensor.LionLanner.exe /install /quiet /norestart CID=5738AB7D43BD43B69165AC612F534C4F-30

cls

echo *** Citrix Workspace app Installation ***
call Citrix\CitrixWorkspaceApp_1912CU2.exe /noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false

cls

echo *** Désinstalation forcée du Office générique ***
call C:\Windows\SysWOW64\Cscript.exe Office\Office365.vbs ALL /Quiet /NoCancel /Force /OSE
call C:\Windows\SysWOW64\Cscript.exe Office\Office15.vbs ALL /Quiet /NoCancel /Force /OSE
echo g > %userprofile%\Deploy.txt
cls
echo *** Faire entrer pour redémarrer ***
pause
shutdown -r -t 00

:APP2
cd %userprofile%\Applications\
TASKKILL /f /im OfficeSetup.exe
START "" "Office\OfficeSetup.exe"

:LOOP
CLS
tasklist | find /i "OfficeSetup" >nul 2>&1
IF ERRORLEVEL 1 (
	GOTO CONTINUE
) ELSE (
	ECHO *** L'instalation d'Office est toujours en cours. ***
	ping 127.0.0.1 -n 6 > nul
	GOTO LOOP
)

:CONTINUE
ECHO *** Fermeture d'Office en cours. ***
ping 127.0.0.1 -n 6 > nul
TASKKILL /f /im OfficeC2RClient.exe
echo *** Installation Teams ***
call Office\TeamsSetup.exe -s
cd ..
echo *** Installation 7Zip ***
call 7zip.exe /S
echo *** Installation Adobe ***
call Adobe.exe /sAll /rs /msi EULA_ACCEPT=YES
echo *** Installation Chrome ***
call MsiExec.exe /i Chrome.msi /qn 
cd Public
copy Public\TeamViewerQS.exe C:\users\public\Desktop
copy "Public\Microsoft Teams.lnk" C:\users\public\Desktop
del %userprofile%\Deploy.txt
cls

set LANDesk = 0
cd "C:\Program Files (x86)\LANDesk"
IF EXIST AdvanceAgent\ set /a LANDesk+=1
IF EXIST LDClient\ set /a LANDesk+=1
IF EXIST PXE\ set /a LANDesk+=1
IF EXIST "Shared Files"\ set /a LANDesk+=1

if %LANDesk% == 4 (
echo Installation de LANDesk OK
) else (
echo Erreur installation de LANDesk
)

where /q sc.exe
IF ERRORLEVEL 1 (
    ECHO Erreur installation Crowstricke 
) ELSE (
    ECHO Installation Crowstricke OK
)

Pause
Clean.cmd