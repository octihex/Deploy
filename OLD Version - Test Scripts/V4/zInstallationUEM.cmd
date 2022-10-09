@echo off
IF EXIST C:\UEM rmdir /S /Q C:\UEM
IF NOT EXIST C:\UEM mkdir C:\UEM
echo *** Transfert des fichiers sur la machine ***
echo %computername% > .\ResultUEM\%computername%.txt
robocopy .\UEM C:\UEM *.* /E > nul
::C:\UEM\UEM.lnk
