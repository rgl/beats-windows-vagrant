Import-Module Carbon
Import-Module "$env:ChocolateyInstall\helpers\chocolateyInstaller.psm1"

$serviceHome = 'C:\kibana'
$serviceName = 'kibana'
$serviceUsername = "NT SERVICE\$serviceName"
$archiveUrl = 'https://artifacts.elastic.co/downloads/kibana/kibana-oss-6.6.1-windows-x86_64.zip'
$archiveHash = 'a87eedbd2820c2e9eaa595f8775c4c98fc4a2f2c37f43b28c3a60b6b0e6db7b95d4a5c2e14911a22e3525ab895e26063b2f1be8543457ba98ce1e08f40422e07'
$archiveName = Split-Path $archiveUrl -Leaf
$archivePath = "$env:TEMP\$archiveName"

Write-Host 'Downloading Kibana...'
(New-Object Net.WebClient).DownloadFile($archiveUrl, $archivePath)
$archiveActualHash = (Get-FileHash $archivePath -Algorithm SHA512).Hash
if ($archiveHash -ne $archiveActualHash) {
    throw "$archiveName downloaded from $archiveUrl to $archivePath has $archiveActualHash hash witch does not match the expected $archiveHash"
}

Write-Host 'Installing Kibana...'
Get-ChocolateyUnzip -FileFullPath $archivePath -Destination $serviceHome
$archiveTempPath = Resolve-Path $serviceHome\kibana-*
Move-Item $archiveTempPath\* $serviceHome
Remove-Item $archiveTempPath
Remove-Item $archivePath

Write-Output "Installing the $serviceName service..."
nssm install $serviceName $serviceHome\bin\kibana.bat
nssm set $serviceName Start SERVICE_AUTO_START
nssm set $serviceName AppDirectory $serviceHome
nssm set $serviceName AppRotateFiles 1
nssm set $serviceName AppRotateOnline 1
nssm set $serviceName AppRotateSeconds 86400
nssm set $serviceName AppRotateBytes (10*1024*1024)
nssm set $serviceName AppStdout $serviceHome\logs\service-stdout.log
nssm set $serviceName AppStderr $serviceHome\logs\service-stderr.log
[string[]]$result = sc.exe sidtype $serviceName unrestricted
if ($result -ne '[SC] ChangeServiceConfig2 SUCCESS') {
    throw "sc.exe sidtype failed with $result"
}
[string[]]$result = sc.exe config $serviceName obj= $serviceUsername
if ($result -ne '[SC] ChangeServiceConfig SUCCESS') {
    throw "sc.exe config failed with $result"
}
[string[]]$result = sc.exe failure $serviceName reset= 0 actions= restart/60000
if ($result -ne '[SC] ChangeServiceConfig2 SUCCESS') {
    throw "sc.exe failure failed with $result"
}

Write-Output "Granting write permissions to selected directories...."
@('optimize', 'data', 'logs') | ForEach-Object {
    $path = "$serviceHome\$_"
    mkdir -Force $path | Out-Null
    Disable-AclInheritance $path
    'Administrators',$serviceUsername | ForEach-Object {
        Write-Host "Granting $_ FullControl to $path..."
        Grant-Permission `
            -Identity $_ `
            -Permission FullControl `
            -Path $path
    }
}

Write-Output "Starting the $serviceName service..."
Start-Service $serviceName

# add default desktop shortcuts (called from a provision-base.ps1 generated script).
[IO.File]::WriteAllText(
    "$env:USERPROFILE\ConfigureDesktop-Kibana.ps1",
@'
[IO.File]::WriteAllText(
    "$env:USERPROFILE\Desktop\Kibana.url",
    @"
[InternetShortcut]
URL=https://kibana.example.com
"@)
'@)
