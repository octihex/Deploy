$Testvar = Get-Credential

Remove-PSDrive -Name "K" -Force -ErrorAction SilentlyContinue
New-PSDrive -Name "K" -PSProvider "FileSystem" -Root "\\FS11LIB1FR\Logiciels" -Persist -Credential $testvar -ErrorAction SilentlyContinue

if (k: -ErrorAction SilentlyContinue) {Write-Host -Object "OK"}
if (!(k: -ErrorAction SilentlyContinue)) {Write-Host -Object "NOK"}