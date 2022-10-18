If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process Powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Unrestricted -NoExit -File "{0}" -Elevated' -F ($Myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}

$Optimizer = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Dell Optimizer"}
$OptimizerUI = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "DellOptimizerUI"}
$Digital = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Dell Digital Delivery Services"}
$OptimizerPath = "C:\Program Files (x86)\InstallShield Installation Information\{286A9ADE-A581-43E8-AA85-6F5D58C7DC88}"

If ($Optimizer)
{
    Write-Host "Stopping Dell Optimizer Service and Removing. . ."
    Stop-Service -Name "Dell Optimizer" -Force -PassThru
    Sc.exe delete DellOptimizer
    Write-Host "Uninstalling Dell Optimizer. . ."
    $Optimizer.Uninstall()
    Clear-Host
}

If ($OptimizerUI)
{
    Write-Host "Uninstalling Dell Optimzer UI. . . "
    $OptimizerUI.Uninstall()
    Clear-Host
}

If ($Digital) 
{
    Write-Host "Uninstalling Dell Digital Delivery Services. . ."
    $Digital.Uninstall()
    Clear-Host
}



If (test-path -path "$OptimizerPath\DellOptimizer.exe" ) 
{
    Start-Process "$OptimizerPath\DellOptimizer.exe" -ArgumentList "-silent -remove -runfromtemp" -NoNewWindow -Wait
    Clear-Host
    Write-Host "Dell Optimizer Services a ete suprime"
}

If (!$Optimizer) 
{
    Write-Host "Dell Optimizer is NOT installed."
}

If (!$Digital) 
{
    Write-Host "Dell Digital Delivery Services is NOT installed."
}

If (!$OptimizerUI) 
{
    Write-Host "Dell Optimizer UI is NOT installed."
}

Pause