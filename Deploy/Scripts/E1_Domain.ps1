#Change le nom de la fenêtre du script
$Host.UI.RawUI.WindowTitle = "Installation Poste - Etape 1 - Domaine"

If (!((Get-CimInstance -ClassName Win32_ComputerSystem).domain -eq "ceva.net")) 
{
    #Arrays pour les normes de nommage
    $ArrLaptops = "LIBLAPOFF", "LIBOL"
    $ArrDesktops = "LIBDESOFF", "LIBOD"

    While ($true) 
    {
        #Récupère le numéro de série et l'affiche pour l'utilisateur
        Write-Host "Numéro de série : " -NoNewline; Write-Host -ForegroundColor Yellow (Get-CimInstance -ClassName Win32_Bios).serialnumber
        #Demande un input a l'utilisateur et stock l'input dans la variable NewNamePC
        $NewNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"

        #La condition dans la commande Switch découpe la variable NewNamePC entre chaque chiffres et lettres
        #Donc Libol18542 deviendra un array qui contient ( Libol 18542 )
        #On récupére la valeur en position 0 de l'array et la compare avec les 2 arrays de nom
        #Si la variable NewNamePC ne contient pas une valeur étant dans les 2 arrays alors on recommence
        Switch (($NewNamePc -split '(?<=\D)(?=\d)')[0]) 
        {
            {$ArrLaptops -eq $_} 
            { 
                Write-Host "Ajout du poste au domaine dans l'OU Laptops avec le nom " -NoNewline; Write-Host -ForegroundColor Yellow -Object $NewNamePc
                Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
                Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
                Add-Computer -DomainName ceva.net -Force -NewName $NewNamePc -OUPath "OU=Laptops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
            }
    
            {$ArrDesktops -eq $_} 
            { 
                Write-Host "Ajout du poste au domaine dans l'OU Desktops avec le nom " -NoNewline; Write-Host -ForegroundColor Yellow -Object $NewNamePc
                Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
                Out-File -FilePath C:\Deploy\Check-Install.txt -Append -Force -InputObject RenameOK | Out-Null
                Add-Computer -DomainName ceva.net -Force -NewName $NewNamePc -OUPath "OU=Desktops,OU=Workstations,OU=Office,OU=Libourne,OU=_FR,DC=ceva,DC=net" -Restart
            }
    
            Default 
            { 
                Clear-Host
                Write-Host -ForegroundColor Yellow $NewNamePc -NoNewline; " Ne respecte pas les normes de nommage des ordinateurs."
            }
        }    
    }
}

Write-Host "Le poste est deja dans le domaine."