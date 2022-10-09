@echo off
cls
::Demande d'input a l'utilisateur pour changer le nom de l'ordinateur
:NEWNAMEgoto
set /p newNamePc="Nouveau nom de l'ordinateur ( exemple LIBLAPOFFxxxxxx )==> "
if not defined newNamePc goto NEWNAMEgoto
echo %newNamePc% > C:\Deploy\newNamePc.txt
call powershell .\newNamePc.ps1
powershell Add-Computer -DomainName ceva.net
cd C:\
Pause
C:\Deploy\Clean.lnk