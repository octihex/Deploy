If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -ExecutionPolicy Unrestricted -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}

$Host.UI.RawUI.WindowTitle = "Installation Poste - Etape 1 - Domaine"
Write-Host "Numéro de série : " -NoNewline; Write-Host -ForegroundColor Yellow (Get-CimInstance -ClassName Win32_Bios).serialnumber

While (!$NewNamePc) 
{
    $NewNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"
}

$ArrLaptops = "Liblapoff", "Libol"
$ArrDesktops = "Libdesoff", "Libod"

Switch (($NewNamePc -split '(?<=\D)(?=\d)')[0]) 
{
    {$ArrLaptops -eq $_} 
    {  
        Write-Host -ForegroundColor Yellow -Object "Ajout du poste au domaine dans l'OU Laptops avec le nom $NewNamePc" 
		#Ajoute le poste au domaine avec le nouveau nom dans l'OU Laptops
        Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Laptops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
    }

    {$ArrDesktops -eq $_}
    {
        Write-Host -ForegroundColor Yellow -Object "Ajout du poste au domaine dans l'OU Desktops avec le nom $NewNamePc"
		#Ajoute le poste au domaine avec le nouveau nom dans l'OU Desktops
        Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -OUPath "OU=Desktops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
    }

    Default 
    {
        Write-Host -ForegroundColor Yellow -Object "Ajout du poste au domaine sans OU spécifique avec le nom $NewNamePc"
		#Ajoute le poste au domaine avec le nouveau nom.
        Add-Computer -DomainName ceva.net -Force -NewName $NewNamePC -Restart
    }
}