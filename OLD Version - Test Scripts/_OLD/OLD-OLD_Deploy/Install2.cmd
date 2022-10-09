@echo off
::Xcopy .\Applications\*.* %userprofile%\Applications /E /H /C /I
robocopy .\Applications\ C:\Deploy\ /MIR /NDL /NJH /NJS | %{$data = $_.Split([char]9); if("$($data[4])" -ne "") { $file = "$($data[4])"} ;Write-Progress "Percentage $($data[0])" -Activity "Robocopy" -CurrentOperation "$($file)"  -ErrorAction SilentlyContinue; }
