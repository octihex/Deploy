

#Change the LocalAdmin user account password, rename the Machine and then reboot the machine

#####################################################################
echo "****************************   Change le mot de passe Admin Local   ****************************"

$Password = ConvertTo-Securestring 'string' -AsPlainText -Force
$UserAccount = Get-LocalUser -Name 'Admin'
$UserAccount | Set-LocalUser -Password $Password

#####################################################################
echo "****************************   Change le default MachineName en 'nompc'   ****************************"

Rename-Computer -NewName 'nompc' 

#####################################################################

Restart-Computer -Force

