function FunctionName 
{
    switch ("test" -eq "test") 
    { 
        Default 
        {
            $testvar = "OK"
            $testvar2 = "OK2"
            Return $testvar, $testvar2    
        }
    }
}

$testarr = FunctionName
$testarr