$Testvar = Get-WindowsUpdate

If (!$Testvar)
{
    Write-Host -Object "Pas de MAJs, On continue"
}

If (Get-WindowsUpdate)
{
    Write-Host -Object "Nouvelle MAJs, On reinstall"
}
