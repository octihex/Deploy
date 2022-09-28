@echo off
Powershell Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
Powershell Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
Powershell .\PreparationPoste.ps1