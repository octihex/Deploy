$Credential = Get-Credential
New-PSDrive -Name "H" -PSProvider "FileSystem" -Root "\\172.20.18.81\Logiciels" -Credential $Credential -Persist
Test-Path -PathType Container H:\