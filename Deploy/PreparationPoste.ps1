$Host.UI.RawUI.WindowTitle = "Installation Poste - Etape 0 - Preparation"

#Chemin de destination du script
$DeployPath = "C:\Deploy"

#Check si le script est lancé avec les permissions Administrateur
If (!((New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) 
{
    #Check si le dossier du script existe et le supprime
    If (test-path -PathType container $DeployPath)
    {
        Remove-Item $DeployPath -Force -Recurse -ErrorAction SilentlyContinue
    }

    #Check si le dossier du script existe et le crée a la racine du disque C
    If (!(test-path -PathType container $DeployPath))
    {
        New-Item -ItemType Directory -Path $DeployPath | Out-Null
    }

    #Crée un fichier dans le dossier Deploy avec le chemin actuel
    #( si dans une clé USB on aurra un chemin "D:\Script\..." )
    #Cette étape est obligatoire sinon une fois le script relancé en Administrateur il n'a plus le chemin de la clé USB mais de System32
    Out-File -FilePath $DeployPath\Get_USB_Path.txt -Force -InputObject (Get-Location).Path | Out-Null

    #Relance le script en Administrateur
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}" -Elevated' -f ($Myinvocation.MyCommand.Definition)) -WindowStyle Maximized
    Exit $LASTEXITCODE
}

#Defini la variable USB_Folder avec le contenu du fichier Get_USB_Path.txt
$USB_Folder = Get-Content -Path $DeployPath\Get_USB_Path.txt

#Débloque l'execution des script dans Powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force -ErrorAction SilentlyContinue

#Désactive l'UAC 
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0

#Configure l'Auto Login
#Sinon après l'ajout du poste dans le domaine il faut cliquer sur se connecter a Ceprt même si le compte n'a pas de MDP
Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -Value "1" -Type String
Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUsername -Value "Ceprt" -type String
Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -Value "" -type String
Set-ItemProperty -Path "REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -Value "Nom de la Machine" -type String

#Copie les fichiers de la clé USB sur le poste
Write-Host -ForegroundColor Yellow -Object "Transfert des fichiers sur le poste"
Copy-Item -Path "$USB_Folder\Deploy\*" -Destination $DeployPath -Recurse

#Copie le raccourci pour le lancement automatique lors du démarrrage
Copy-Item -Path "$DeployPath\Deploy.lnk" -Destination "C:\Users\ceprt\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

#Lance le script principal
Start-Process Powershell -ArgumentList "$DeployPath\Deploy.ps1" -NoNewWindow