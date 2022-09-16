$host.UI.RawUI.WindowTitle = "Script check d'installation poste CEVA"
#Verifie si le script est lancer avec des permissions administrateur.
if (!$(net session *>$null; $LASTEXITCODE -eq 0))
{
    Write-Host -ForegroundColor Yellow -Object "Ce script a besoin d'etre ouvert avec permissions d'administrateurs."
    exit
}
