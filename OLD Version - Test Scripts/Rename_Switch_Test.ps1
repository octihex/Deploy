$newNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"

$ArrLaptops = "Libla", "Libol"
$ArrDesktops = "Libde", "Libod"

switch ($newNamePc.Substring(0,5)) 
{
    {$ArrLaptops -eq $_} 
    { 
        "You entered Lap." 
    }

    {$ArrDesktops -eq $_} 
    { 
        "You entered Des." 
    }

    Default 
    { 
        "You didn't enter PC."
    }
}