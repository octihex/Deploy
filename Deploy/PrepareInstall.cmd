@echo off

IF EXIST C:\Deploy rmdir /S /Q C:\Deploy
IF NOT EXIST C:\Deploy mkdir C:\Deploy
PowerShell (Get-Location).Path > C:\Deploy\GetFolder.txt

PowerShell -ExecutionPolicy Unrestricted -File .\PreparationPoste.ps1