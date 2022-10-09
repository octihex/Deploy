$Testvar = Get-WindowsUpdate

If (!$Testvar)
{
    Write-Host -Object "Pas de MAJs, On continue"
}

If ($Testvar)
{
    Write-Host -Object "Nouvelle MAJs, On reinstall"
}
