$DeployPath = 'C:\Deploy'

If(test-path -PathType container $DeployPath)
{
    Remove-Item $DeployPath -Force  -Recurse -ErrorAction SilentlyContinue
}

If(!(test-path -PathType container $DeployPath))
{
    New-Item -ItemType Directory -Path $DeployPath | Out-Null
}

Write-Host -ForegroundColor Yellow -Object "Transfert des fichiers sur le poste"
Copy-Item -Path ".\Deploy\*" -Destination $DeployPath -Recurse
Start-Process powershell -verb runas -ArgumentList "$DeployPath\Deploy.ps1"