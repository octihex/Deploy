$host.UI.RawUI.WindowTitle = "Script check d'installation poste CEVA"
#Verifie si le script est lancer avec des permissions administrateur.
if (!$(net session *>$null; $LASTEXITCODE -eq 0))
{
    Write-Host -ForegroundColor Yellow -Object "Ce script a besoin d'etre ouvert avec permissions d'administrateurs."
    exit
}











$testvar = Get-WindowsUpdate

if ($testvar) {
    Write-Host "Il y a encore des MAJ"
} 
else {
    Write-Host "Il n'y a plus de MAJ"
}