While (!$NewNamePc) 
{
    $NewNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"
}

$ArrLaptops = "Liblapoff", "Libol"
$ArrDesktops = "Libdesoff", "Libod"

switch (($NewNamePc -split '(?<=\D)(?=\d)')[0]) 
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