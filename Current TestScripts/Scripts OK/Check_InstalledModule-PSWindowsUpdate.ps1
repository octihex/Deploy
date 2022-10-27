If (!(Get-InstalledModule -Name PSWindowsUpdate -ErrorAction SilentlyContinue))
{
    Write-Host -Object "NOK"
}

If (Get-InstalledModule -Name PSWindowsUpdate -ErrorAction SilentlyContinue)
{
    Write-Host -Object "OK"
}