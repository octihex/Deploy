$DeployPath = "C:\Deploy"
$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
$testadmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

if ($testadmin -eq $false) 
{
    If (test-path -PathType container $DeployPath)
    {
        Remove-Item $DeployPath -Force -Recurse -ErrorAction SilentlyContinue
    }

    If (!(test-path -PathType container $DeployPath))
    {
        New-Item -ItemType Directory -Path $DeployPath | Out-Null
    }

    if (!(Test-Path -PathType leaf -Path "C:\Deploy\Manufacturer.txt")) 
    {
        foreach ($line in (Get-CimInstance -ClassName Win32_ComputerSystem).manufacturer)
        {
            $Manufacturer = ($line.Split(" "))[0]
        }

        if (Select-String -InputObject $Manufacturer -Pattern Lenovo) 
        {   
            Out-File -FilePath $DeployPath\Manufacturer.txt -Force -InputObject Lenovo | Out-Null
        }

        elseif (Select-String -InputObject $Manufacturer -Pattern Dell) 
        {
            Out-File -FilePath $DeployPath\Manufacturer.txt -Force -InputObject Dell | Out-Null
        }

        else 
        {
            Write-Host -Object "Ce script n'est pas prévu pour cette marque d'appareil, le script va se fermer."
            Pause
            exit
        }
    }

    foreach ($line in (Get-CimInstance -ClassName Win32_ComputerSystem).manufacturer)
    {
        $Manufacturer = ($line.Split(" "))[0]
    }

    if (Select-String -InputObject $Manufacturer -Pattern Lenovo) 
    {   
        Out-File -FilePath $DeployPath\Manufacturer.txt -Force -InputObject Lenovo | Out-Null
    }

    elseif (Select-String -InputObject $Manufacturer -Pattern Dell) 
    {
        Out-File -FilePath $DeployPath\Manufacturer.txt -Force -InputObject Dell | Out-Null
    }

    else 
    {
        Write-Host -Object "Ce script n'est pas prévu pour cette marque d'appareil, le script va se fermer."
        Pause
        exit
    }

    Out-File -FilePath $DeployPath\Get_USB_Path.txt -Force -InputObject (Get-Location).Path | Out-Null
    Start-Process powershell.exe -ExecutionPolicy Bypass -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition)) 
    exit $LASTEXITCODE
}

$USB_Folder = Get-Content -Path $DeployPath\Get_USB_Path.txt

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0

Write-Host -ForegroundColor Yellow -Object "Transfert des fichiers sur le poste"
Copy-Item -Path "$USB_Folder\*" -Destination $DeployPath -Recurse
Copy-Item -Path "$DeployPath\Deploy.lnk" -Destination "C:\Users\ceprt\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
Start-Process Powershell -ArgumentList "$DeployPath\Deploy.ps1"