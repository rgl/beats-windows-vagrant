# NB filebeat is run as SYSTEM as a simple way to be able to read any log files.

$serviceHome = 'C:\filebeat'
$serviceName = 'filebeat'
$archiveUrl = 'https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-6.5.4-windows-x86_64.zip'
$archiveHash = 'f9f08ab2bdccf25328d59b34da67b8bb5f0cc92be5c9d385fd350a570a4d2d7460c8514fb495c19bcc81462d4b077e33579369a1e0d3b0ed7439394ac3ab0a8f'
$archiveName = Split-Path $archiveUrl -Leaf
$archivePath = "$env:TEMP\$archiveName"

# wrap filebeat.exe to prevent PowerShell from stopping the script
# when there is data in stderr.
function filebeat {
    $eap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        &"$serviceHome\filebeat.exe" -e @Args 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                "$_"
            } else {
                "$_"
            }
        }
        if ($LASTEXITCODE) {
            throw "filebeat failed to execute with exit code $LASTEXITCODE"
        }
    } finally {
        $ErrorActionPreference = $eap
    }
}

Write-Host 'Downloading filebeat...'
(New-Object Net.WebClient).DownloadFile($archiveUrl, $archivePath)
$archiveActualHash = (Get-FileHash $archivePath -Algorithm SHA512).Hash
if ($archiveHash -ne $archiveActualHash) {
    throw "$archiveName downloaded from $archiveUrl to $archivePath has $archiveActualHash hash witch does not match the expected $archiveHash"
}

Write-Host 'Installing filebeat...'
mkdir $serviceHome | Out-Null
Expand-Archive $archivePath -DestinationPath $serviceHome
$archiveTempPath = Resolve-Path $serviceHome\filebeat-*
Move-Item $archiveTempPath\* $serviceHome
Remove-Item $archiveTempPath
Remove-Item $archivePath

Write-Output "Installing the $serviceName windows service..."
New-Service `
    -Name $serviceName `
    -StartupType 'Automatic' `
    -BinaryPathName (@(
        "$serviceHome\filebeat.exe"
        "-c $serviceHome\filebeat.yml"
        "-path.home $serviceHome"
    ) -join ' ') `
    | Out-Null
[string[]]$result = sc.exe failure $serviceName reset= 0 actions= restart/60000
if ($result -ne '[SC] ChangeServiceConfig2 SUCCESS') {
    throw "sc.exe failure failed with $result"
}
'tls','data','logs' | ForEach-Object {
    mkdir $serviceHome\$_ | Out-Null
    Disable-AclInheritance $serviceHome\$_
    Grant-Permission $serviceHome\$_ SYSTEM FullControl
    Grant-Permission $serviceHome\$_ Administrators FullControl
}
Move-Item $serviceHome\filebeat.yml $serviceHome\filebeat-dist.yml 
Copy-Item c:\vagrant\filebeat.yml $serviceHome
Copy-Item c:\vagrant\shared\beats-example-ca\beats-example-ca-crt.pem $serviceHome\tls

Write-Output "Testing the configuration file..."
filebeat test config

Write-Output "Enabling modules..."
filebeat modules enable iis
filebeat modules list

Write-Output "Setting up elasticsearch and kibana..."
filebeat setup

Write-Output "Starting the $serviceName service..."
Start-Service $serviceName
