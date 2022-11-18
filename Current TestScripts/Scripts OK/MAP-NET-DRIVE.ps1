$Credential = Get-Credential

Remove-PSDrive -Name "H" -Force -ErrorAction SilentlyContinue
New-PSDrive -Name "H" -PSProvider "FileSystem" -Root "\\172.20.18.81\Logiciels" -Credential $Credential -Persist