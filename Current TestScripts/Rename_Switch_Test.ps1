$ArrLaptops = "LIBLAPOFF", "LIBOL"
$ArrDesktops = "LIBDESOFF", "LIBOD"

While (!$Testtruc) 
{
    $NewNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"

    Switch (($NewNamePc -split '(?<=\D)(?=\d)')[0]) 
    {
        {$ArrLaptops -eq $_} 
        { 
            "LAP"
            $Testtruc = "OK"
        }
    
        {$ArrDesktops -eq $_} 
        { 
            "DESK"
            $Testtruc = "OK"
        }
    
        Default 
        { 
            "Default"
        }
    }    
}