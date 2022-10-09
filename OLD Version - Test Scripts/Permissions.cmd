@echo off

:CHEMINgoto
cls
set /p CHEMIN="Chemin du FICHIER ou DOSSIER ==> "
if not defined CHEMIN goto CHEMINgoto

:LOGINgoto
cls
set /p LOGIN="Identifient Windows Utilisateur ==> "
if not defined LOGIN goto LOGINgoto

:PERMISSIONSgoto
cls
set /p PERMISSIONS="Option de permissions ==> "
if not defined PERMISSIONS goto PERMISSIONSgoto

:OPERATORgoto
cls
echo ajouter ou retirer des permissions ?
set /p OPERATOR=" (1) ajouter | (2) retirer ==> "
if not defined OPERATOR goto OPERATORgoto

IF "%OPERATOR%"=="1" (
SET "CA1=grant"
) ELSE (
IF "%OPERATOR%"=="2" (
SET "CA1=deny"
) ELSE (
goto OPERATORgoto
)
)

:FILEDERgoto
cls
echo Modifier un Fichier ou un Dossier ?
set /p Fileder=" (1) Fichier | (2) Dossier ==> "
if not defined Fileder goto FILEDERgoto

IF "%Fileder%"=="1" (
goto FICHIERgoto
) ELSE (
IF "%Fileder%"=="2" (
goto DOSSIERgoto
) ELSE (
goto FILEDERgoto
)
)

:FICHIERgoto

icacls.exe %CHEMIN% /%CA1% "%LOGIN%:(%PERMISSIONS%)"
pause
goto :eof

:DOSSIERgoto

icacls.exe %CHEMIN% /%CA1% "%LOGIN%:(OI)(CI)(%PERMISSIONS%)"
pause
goto :eof