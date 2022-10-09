@echo off
powershell Set-Culture en-US
ping 127.0.0.1 -n 2 > nul
call "D:\Games\Assassins Creed Origins\ACOrigins.exe"
powershell Set-Culture fr-FR
robocopy C:\Users\Public\Documents\uPlay\CODEX\Saves\UnnamedGame\ C:\Users\Public\Documents\uPlay\CODEX\Saves\UnnamedGame_Backup\ *.* /MIR
exit