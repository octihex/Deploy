$Cleaning_REG_PATH = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

If (!(Get-ItemProperty -Path $Cleaning_REG_PATH -Name Run) | Out-Null)
{
    Write-Host -Object "NOK"
}

Else
{
    Write-Host -Object "OK"
}
