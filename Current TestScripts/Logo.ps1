$EFI_Drive_Letter = "Y"
$BGRT_Path = "${EFI_Drive_Letter}:\EFI\HackBGRT"

#Détection auto de la partition de Boot
Get-Partition | Where-Object {$_.Type -like "System"} | Set-Partition -NewDriveLetter $EFI_Drive_Letter

#Check si la partition de boot a la bonne lettre de disque
If (!((Get-Volume -FileSystemLabel ESP).DriveLetter -eq $EFI_Drive_Letter))
{
    "Erreur dans la detection de la partition ESP"
    Pause
    Exit
}

#Copie de Splash.bmp et Config.txt dans le chemin de HackBGRT
New-Item -ItemType Directory -Path $BGRT_Path | Out-Null
Copy-Item -Path ".\HackBGRT\*" -Destination $BGRT_Path -Recurse

#Backup du fichier de boot de Windows
Copy-Item -Path "${EFI_Drive_Letter}:\EFI\Microsoft\Boot\bootmgfw.efi" -Destination "$BGRT_Path\bootmgfw-original.efi" -Recurse

#Instalation du fichier de boot de HackBGRT
Set-Location ${EFI_Drive_Letter}:\
bcdedit /set {bootmgr} path \EFI\HackBGRT\HackBGRT.efi
bcdedit /set {bootmgr} description "HackBGRT Boot Manager"