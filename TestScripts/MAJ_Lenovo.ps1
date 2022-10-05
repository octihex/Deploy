#Fonction de MAJ Lenovo
function MAJ_Lenovo 
{
  	$host.UI.RawUI.WindowTitle = "Installation Poste - Etape 3 - MAJ Lenovo"

  	#Recherche et installe toutes les MAJ Dell disponible
  	Write-Host -ForegroundColor Yellow -Object "Recherche des MAJ Lenovo"

  	#Configure Dell Command Update et cherche les MAJ disponible
  	Clear-Host

  	#Installe toutes les MAJ
  	Write-Host -ForegroundColor Yellow -Object "Installation des MAJ Dell"
  	Clear-Host
  	Out-File -FilePath $DeployPath\Check-Install.txt -Append -Force -InputObject MAJConstructeursOK | Out-Null
  	Restart-Computer
}