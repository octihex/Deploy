# http://woshub.com/how-to-disable-password-login-in-windows-10/

$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "Ceprt" -type String
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "" -type String
Set-ItemProperty $RegistryPath 'DefaultDomainName' -Value "Nom de la Machine" -type String