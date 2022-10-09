@echo off
::Ouvre le menu Windows Update
control update

::Recherche et installe les MAJ Dell depuis le Dell Command Update en ligne de commande
call "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /configure -silent -autoSuspendBitLocker=enable -userConsent=disable
ping 127.0.0.1 -n 3 > nul
cls
call "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /scan -outputLog=C:\dell\logs\scan.log
ping 127.0.0.1 -n 3 > nul
cls
call "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" /applyUpdates -reboot=disable -outputLog=C:\dell\logs\applyUpdates.log

::Demande d'input a l'utilisateur pour changer le nom de l'ordinateur
:NEWNAMEgoto
set /p newNamePc="Nouveau nom de l'ordinateur ( exemple LIBLAPOFFxxxxxx )==> "
if not defined newNamePc goto NEWNAMEgoto

::Demande a l'utilisateur de choisir entre Laptop ou Desktop
echo %newNamePc% > C:\Deploy\Powershell\newNamePc.txt
:OUgoto
cls
echo Ajouter un Laptop ou un Desktop ?
set /p OU=" (1) Laptop | (2) Desktop ==> "
if not defined OU goto OUgoto

::Si Laptop il va placer l'ordinateur dans l'OU Laptops
::Si Desktop il va placer l'ordinateur dans l'OU Desktop
IF "%OU%"=="1" (
call powershell C:\Deploy\Powershell\newNamePcLaptops.ps1
) ELSE (
IF "%OU%"=="2" (
call powershell C:\Deploy\Powershell\newNamePcDesktops.ps1
) ELSE (
goto OUgoto
)
)

::Installation de Citrix
echo *** Installation Citrix ***
call C:\Deploy\Citrix\CitrixWorkspaceApp.exe /noreboot /silent /AutoUpdateCheck=Disabled EnableCEIP=false EnableTracing=false
cls

::Installation Windows Defender
echo *** Installation de Windows Defender ***
call C:\Deploy\Defender\WindowsDefender.cmd
cls

::Installation de LANDesk
echo *** Installation LANDesk ***
call msiexec /i C:\Deploy\UEM\LANDesk.msi
cls

::Desinstallation d'Office 15 et d'Office click to run 
echo *** Desinstalation forcee du Office generique ***
call C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office\Office365.vbs ALL /Quiet /NoCancel /Force /OSE
call C:\Windows\SysWOW64\Cscript.exe C:\Deploy\Office\Office15.vbs ALL /Quiet /NoCancel /Force /OSE
cls

::Installation d'Office
TASKKILL /f /im OfficeSetup.exe
START "" "C:\Deploy\Office\OfficeSetup.exe"

::Installation de Teams
echo *** Installation Teams ***
call C:\Deploy\Office\TeamsSetup.exe -s

::Installation de 7Zip
echo *** Installation 7Zip ***
call C:\Deploy\Apps\7zip.exe /S

::Installation d'Adobe Reader DC
echo *** Installation Adobe ***
call C:\Deploy\Apps\Adobe.exe /sAll /rs /msi EULA_ACCEPT=YES

::Installation de Google Chrome
echo *** Installation Chrome ***
call MsiExec.exe /i C:\Deploy\Apps\Chrome.msi /qn 

::Copie TeamViewerQS.exe et Microsoft Teams.lnk dans le bureau public
robocopy C:\Deploy\Public C:\users\public\Desktop *.* /E > nul
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

::Verifie que LANDesk s'est bien installer en comptant les dossiers
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
IF EXIST "C:\Program Files (x86)\LANDesk\Shared Files\" set /a LANDesk+=1
IF %LANDesk% == 4 (
	GOTO CONTINUEUEM
) ELSE (
	ECHO *** L'instalation de LANDesk est toujours en cours. ***
	ping 127.0.0.1 -n 6 > nul
	set /a DebugCounterLANDesk+=1
	GOTO LOOPUEM
)

:CONTINUEUEM
shutdown -r -t 5
cd C:\
C:\Deploy\Clean.lnk