if (!(Get-SMBSession -ErrorAction SilentlyContinue)) 
{
    Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    Exit $LASTEXITCODE
}