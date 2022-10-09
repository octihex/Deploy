@echo off
IF EXIST C:\Deploy rmdir /S /Q C:\Deploy
IF NOT EXIST C:\Deploy mkdir C:\Deploy
echo *** Transfert des fichiers sur la machine ***
robocopy .\Deploy C:\Deploy *.* /E > nul
C:\Deploy\Deploy.lnk
