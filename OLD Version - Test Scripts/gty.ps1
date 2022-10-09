
function Function-RenamePc {
    if (Get-Process notepad -ErrorAction SilentlyContinue) {
        Write-Host -Object "*** OK ***"
        Break
    }
    else {
        Write-Host -Object "*** NO ***"
        Start-Sleep -Seconds 2
        Function-RenamePc
    }
}

Function-RenamePc
Write-Host -Object "*** OK2 ***"