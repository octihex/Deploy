@echo off
:LOOP
CLS
set LANDesk=0
cd "D:\testvar"
IF EXIST t1\ set /a LANDesk+=1
IF EXIST t2\ set /a LANDesk+=1
IF EXIST t3\ set /a LANDesk+=1
IF EXIST "t4"\ set /a LANDesk+=1
IF %LANDesk% == 4 (
	GOTO CONTINUE
) ELSE (
	ECHO *** Test en cours. ***
	ping 127.0.0.1 -n 3 > nul
	GOTO LOOP
)
:CONTINUE
echo OK
pause