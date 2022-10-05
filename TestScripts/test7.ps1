$newNamePc = Read-Host -Prompt "Nouveau nom de l'ordinateur"
<#
If ($newNamePc.Length -ge 5)
{
    Switch ($newNamePc.Substring(0,5)) {
        Libla 
        {  
            Write-Host -Object "Liblapoff"
        }

        Libde
        {
            Write-Host -Object "Libdesoff"
        }

        Libol
        {
            Write-Host -Object "Libol"
        }

        Libod
        {
            Write-Host -Object "Libod"
        }

        Default 
        {
            Write-Host -Object "Nope"
        }
    }
}

Else 
{
    Write-Host -Object "Le nom du poste doit au moins contenir 5 characters"
}
#>

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
    Default { "You didn't enter PC."}
}