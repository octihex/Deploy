@echo off

::Installation de LANDesk
echo *** Installation LANDesk ***
msiexec /i C:\Deploy\UEM\LANDesk.msi

::Vérifie que LANDesk s'est bien installer avec une variable incrémenter avec chaque dossiers
set LANDesk = 0
cd "C:\Program Files (x86)\LANDesk"
IF EXIST AdvanceAgent\ set /a LANDesk+=1
IF EXIST LDClient\ set /a LANDesk+=1
IF EXIST PXE\ set /a LANDesk+=1
IF EXIST "Shared Files"\ set /a LANDesk+=1
::Si la variable LANDesk est égale a 4 l'instalation s'est bien passée
if %LANDesk% == 4 (
echo Installation de LANDesk OK
) else (
echo Erreur installation de LANDesk
)
Pause
cd C:\
C:\Deploy\Clean.lnk