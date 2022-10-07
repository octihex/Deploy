$DeployPath = "C:\Deploy"

Start-Process -FilePath "$DeployPath\Apps\Lenovo_SU.exe" -ArgumentList "/VERYSILENT /NORESTART" -NoNewWindow -Wait
Winget Install 9WZDNCRFJ4MV --Source Msstore --Accept-Source-Agreements --Accept-Package-Agreements