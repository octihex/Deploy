$testvar = Read-Host -Prompt "test"

if (!$testvar) 
{
	Write-Host -Object "null"
}

if ($testvar) 
{
	Write-Host -Object "pas null"
}
