function test1 {
    if (!((Get-Content -Path c:\Deploy\Check-Install.txt)[-1] -eq "test2")) {
        Write-Host -Object "pas ok"
    }
    if ((Get-Content -Path c:\Deploy\Check-Install.txt)[-1] -eq "test2") {
        Write-Host -Object "ok"
    }
}
test1