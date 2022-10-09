@echo off

c:
cd %userprofile%
ping 127.0.0.1 -n 3 > nul
rmdir /S /Q Applications
del Deploy.txt