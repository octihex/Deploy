If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process Powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Unrestricted -NoExit -File "{0}" -Elevated' -F ($Myinvocation.MyCommand.Definition)) -WindowStyle Maximized
    Exit $LASTEXITCODE
}

Clear-Host
Write-Output "Détection automatique de Dell Optimizer en cours"
$Optimizer = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Dell Optimizer"}

Clear-Host
Write-Host "Détection automatique de Dell Optimizer en cours."
$OptimizerUI = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "DellOptimizerUI"}

Clear-Host
Write-Host "Détection automatique de Dell Optimizer en cours.."
$Digital = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Dell Digital Delivery Services"}

Clear-Host
Write-Host "Détection automatique de Dell Optimizer en cours..."
$OptimizerPath = "C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}"

If ($Optimizer)
{
    Write-Host "Fermeture des services Dell Optimizer en cours."
    Stop-Service -Name "Dell Optimizer" -Force -PassThru
    Sc.exe Delete DellOptimizer
    Write-Host "Désinstallation de Dell Optimizer en cours."
    $Optimizer.Uninstall()
    Clear-Host
}

If ($OptimizerUI)
{
    Write-Host "Désinstallation de Dell Optimzer UI en cours."
    $OptimizerUI.Uninstall()
    Clear-Host
}

If ($Digital) 
{
    Write-Host "Désinstallation des Services de Dell Optimzer."
    $Digital.Uninstall()
    Clear-Host
}


If (Test-Path -Path "$OptimizerPath\DellOptimizer.exe") 
{
    Start-Process "$OptimizerPath\DellOptimizer.exe" -ArgumentList "-silent -remove -runfromtemp" -NoNewWindow -Wait
    Remove-Item $OptimizerPath -Force -Recurse -ErrorAction SilentlyContinue
    Clear-Host
    Write-Host "La version universelle de Dell Optimzer a été désinstaller."
}

If (!$Optimizer -Or !$OptimizerUI -Or !$Digital) 
{
    Write-Host "Dell Optimizer n'est pas installée."
}

Pause