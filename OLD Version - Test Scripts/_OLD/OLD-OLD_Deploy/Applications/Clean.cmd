@echo off

c:
ping 127.0.0.1 -n 3 > nul
rmdir /S /Q %userprofile%\Applications
del %userprofile%\Deploy.txt
del "C:\Users\ceprt\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Deploy.lnk"