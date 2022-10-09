#C:\Windows\explorer.exe ms-settings:windowsupdate-action | PowerShell.exe (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
$oInstaller=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller()
$aUpdates=New-Object -ComObject Microsoft.Update.UpdateColl
((New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0 and Type='Software'")).Updates|%{
    if(!$_.EulaAccepted){$_.EulaAccepted=$true}
    [void]$aUpdates.Add($_)
}
$oInstaller.ForceQuiet=$true
$oInstaller.Updates=$aUpdates
if($oInstaller.Updates.count -ge 1){
  write-host "Installing " $oInstaller.Updates.count "Updates"
  if($oInstaller.Install().RebootRequired){Restart-Computer}
} else {
  write-host "No updates detected"
}