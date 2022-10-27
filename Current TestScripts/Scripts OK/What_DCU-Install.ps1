If (Test-Path -PathType leaf -Path "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe")
{
    $DCU_Path = "C:\Program Files (x86)\Dell\CommandUpdate"
}

If (Test-Path -PathType leaf -Path "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe")
{
    $DCU_Path = "C:\Program Files\Dell\CommandUpdate"
}

if (!$DCU_Path) 
{
    Write-Host "Trouve pas DCU"
}

