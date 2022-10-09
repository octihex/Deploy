While (Get-Process notepad -ErrorAction SilentlyContinue)
{
  Write-Host -Object "*** NO ***"
  Start-Sleep -Seconds 2
}
Write-Host -Object "*** OK ***"