$testvar = Get-WindowsUpdate

if ($testvar) {
    Write-Host "Il y a encore des MAJ"
} 
else {
    Write-Host "Il n'y a plus de MAJ"
}