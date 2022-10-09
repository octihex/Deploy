@ECHO OFF

:NEWNAMEgoto
set /p newName="Nouveau nom de l'ordinateur ( exemple LIBLAPOFFxxxxxx )==> "
if not defined newName goto NEWNAMEgoto

echo WMIC computersystem where caption='%computername%' rename %newName%

powershell Add-Computer -DomainName ceva.net

pause