$Cleaning_REG_PATH = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

if (!(Get-ItemProperty -Path $Cleaning_REG_PATH -Name Run) | Out-Null)
  {
    Write-Host -Object "NOK"
  }
else
  {
    Write-Host -Object "OK"
  }
