$Login = "test"
$admin = "test"
$panel = "test"

Function TestFunc ()
{
    if ($true -eq $panel) 
    {
        if ($true -eq $Login) 
        {
            if ($true -eq $admin) 
            {
                "admin"
            }

            else 
            {
                "pas admin"
            }
        }

        else 
        {
            "pas login"
        }
    }

    else 
    {
        "pas panel"
    }
}

Function TestFunc2 ()
{
    if ($true -eq $panel) 
    {
        if ($true -eq $Login) 
        {
            if ($true -eq $admin) 
            {
                "admin"
            }

            else 
            {
                "pas admin"
            }
        }

        else 
        {
            "pas login"
        }
    }

    else 
    {
        "pas panel"
    }
}