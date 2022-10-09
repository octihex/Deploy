@echo off

::Installation de Citrix
echo *** Installation Citrix ***
start C:\Deploy\CitrixWorkspaceApp.exe /noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false
cls

::Installation de LANDesk
echo *** Installation LANDesk ***
msiexec /i C:\Deploy\LANDesk.msi
cls

::Installation de Windows Defender
echo *** Installation Windows Defender ***
call C:\Deploy\WindowsDefender.cmd
cls

::Desinstallation d'Office 15 et d'Office click to run 
echo *** Desinstalation forcee du Office generique ***
call C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office365.vbs ALL /Quiet /NoCancel /Force /OSE
call C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office15.vbs ALL /Quiet /NoCancel /Force /OSE
cls

::Installation d'Office
TASKKILL /f /im OfficeSetup.exe
START "" "C:\Deploy\OfficeSetup.exe"

::Installation de Teams
echo *** Installation Teams ***
call C:\Deploy\TeamsSetup.exe -s

::Installation de 7Zip
echo *** Installation 7Zip ***
call C:\Deploy\7zip.exe /S

::Installation d'Adobe Reader DC
echo *** Installation Adobe ***
call C:\Deploy\Adobe.exe /sAll /rs /msi EULA_ACCEPT=YES

::Installation de Google Chrome
echo *** Installation Chrome ***
call MsiExec.exe /i C:\Deploy\Chrome.msi /qn 

::Copie TeamViewerQS.exe et Microsoft Teams.lnk dans le bureau public
copy C:\Deploy\TeamViewerQS.exe C:\users\public\Desktop
copy "C:\Deploy\Microsoft Teams.lnk" C:\users\public\Desktop
cls

::Attend la fin de l'instalation d'Office pour continuer
:LOOPOFFICE
CLS
tasklist | find /i "OfficeSetup" >nul 2>&1
IF ERRORLEVEL 1 (
	GOTO CONTINUEOFFICE
) ELSE (
	ECHO *** L'instalation d'Office est toujours en cours. ***
	ping 127.0.0.1 -n 6 > nul
	GOTO LOOPOFFICE
)

::Ferme de force la fenetre de fin d'instalation d'Office
:CONTINUEOFFICE
ECHO *** Fermeture d'Office en cours. ***
ping 127.0.0.1 -n 6 > nul
TASKKILL /f /im OfficeC2RClient.exe
cls

::Verifie que LANDesk s'est bien installer avec une variable qui augmante avec chaque dossiers
echo *** Installation LANDesk ***
set DebugCounterLANDesk=0
msiexec /i C:\UEM\LANDesk.msi
:LOOPUEM
CLS
IF %DebugCounterLANDesk% == 36 (
	C:\UEM\DebugInstallLANDesk.lnk
	set /a DebugCounterLANDesk+=1
)
set LANDesk=0
cd "C:\Program Files (x86)\LANDesk"
IF EXIST "C:\Program Files (x86)\LANDesk\AdvanceAgent\" set /a LANDesk+=1
IF EXIST "C:\Program Files (x86)\LANDesk\LDClient\" set /a LANDesk+=1
IF EXIST "C:\Program Files (x86)\LANDesk\PXE\" set /a LANDesk+=1
IF EXIST "C:\Program Files (x86)\LANDesk\Shared Files"\ set /a LANDesk+=1
IF %LANDesk% == 4 (
	GOTO CONTINUEUEM
) ELSE (
	ECHO *** L'instalation de LANDesk est toujours en cours. ***
	timeout /t 5 /nobreak
	set /a DebugCounterLANDesk+=1
	GOTO LOOPUEM
)

::Si la variable LANDesk est egale a 4 l'instalation s'est bien passee
:CONTINUEUEM
if %LANDesk% == 4 (
echo Installation de LANDesk OK
) else (
echo Erreur installation de LANDesk
)

::Cherche dans le PATH de Windows si sc.exe ( Crowstricke ) existe 
where /q sc.exe
IF ERRORLEVEL 1 (
    ECHO Erreur installation Crowstricke 
) ELSE (
    ECHO Installation Crowstricke OK
)

pause
cd C:\
C:\Deploy\Clean.lnk