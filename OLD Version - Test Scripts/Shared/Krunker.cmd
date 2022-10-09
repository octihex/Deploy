@echo off

netsh interface set interface Vigor enable
netsh interface set interface Ethernet disable
ping 127.0.0.1 -n 4 > nul
call "F:\Softwares\Steam\steamapps\common\Krunker\Official Krunker.io Client.exe"
netsh interface set interface Ethernet enable
netsh interface set interface Vigor disable
exit