Import-Module ServerManager

function Update-Object(
    $target,
    [hashtable]$source,
    $currentPath = ''
) {
    $source.Keys | ForEach-Object {
        $propertyPath = "$currentPath.$_"
        $desiredValue = $source[$_]
        $valueIsHash = [hashtable].IsAssignableFrom($desiredValue.GetType())
        $currentValue = $target.$_
        if ($valueIsHash) {
            Update-Object $currentValue $desiredValue $propertyPath
        } else {
            if ($currentValue -ne $desiredValue) {
                $target.$_ = $desiredValue
            }
        }
    }
}

# NB use Get-WindowsFeature | Format-Table -AutoSize | Out-String -Width 1024 to list all the available features.
Write-Host 'Installing IIS and its management tools...'
Install-WindowsFeature `
    Web-Default-Doc,
    Web-Http-Errors,
    Web-Http-Logging,
    Web-Http-Tracing,
    Web-Static-Content,
    Web-Asp-Net45 `
    -IncludeManagementTools

Write-Host 'Configuring IIS logging...'
# NB this modifies %windir%\system32\inetsrv\config\applicationHost.config
# NB you can see the IIS schema at %windir%\system32\inetsrv\config\schema\IIS_schema.xml
# NB you can get the current configuration with, e.g.:
#       Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/logFile'
#       Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites/siteDefaults/logFile' -Name 'logExtFileFlags'
Set-WebConfigurationProperty `
    -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.applicationHost/sites/siteDefaults/logFile' `
    -Name 'logExtFileFlags' `
    -Value 'Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer,ProtocolVersion,Host,HttpSubStatus'

Write-Host 'Enabling the IIS proxy...'
choco install -y iis-arr
# NB this modifies %windir%\system32\inetsrv\config\applicationHost.config
# NB you can see the ARR schema at %windir%\system32\inetsrv\config\schema\arr_schema.xml
# NB you can get the current configuration with, e.g.:
#       Get-WebConfiguration -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer'
#       Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'preserveHostHeader'
Set-WebConfigurationProperty `
    -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.webServer/proxy' `
    -Name 'enabled' `
    -Value 'true'
Set-WebConfigurationProperty `
    -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.webServer/proxy' `
    -Name 'preserveHostHeader' `
    -Value 'true' # NB default: false
Set-WebConfigurationProperty `
    -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.webServer/proxy' `
    -Name 'reverseRewriteHostInResponseHeaders' `
    -Value 'true' # NB default: true
# do not send the ARR "X-Powered-By" response header.
Set-WebConfigurationProperty `
    -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.webServer/proxy' `
    -Name 'arrResponseHeader' `
    -Value 'false'

# configure the reverse-proxy.
@{
    'elasticsearch.example.com' = '* http://127.0.0.1:9200/{R:0}'
    'kibana.example.com'        = '* http://127.0.0.1:5601/{R:0}'
}.GetEnumerator() | ForEach-Object {
    $siteName = $_.Name
    $uri = [uri]"https://$siteName"

    # create the app pool.
    $appPoolPath = "IIS:\AppPools\$siteName"
    if (!(Test-Path $appPoolPath)) {
        Write-Host "Creating the $siteName application pool..."
        $appPool = New-Item $appPoolPath
        Update-Object -Target $appPool -Source @{
            startMode = 'AlwaysRunning'
            managedRuntimeVersion = 'v4.0'
            managedPipelineMode = 'Integrated'
            processModel = @{
                idleTimeout = [TimeSpan]::Zero
                identityType = 'ApplicationPoolIdentity'
            }
            recycling = @{
                periodicRestart = @{
                    time = [TimeSpan]::Zero
                }
            }
        }
        $appPool | Set-Item
    }

    # create the site.
    $website = Get-Website -Name $siteName
    if ($null -eq $website) {
        $certificate = Get-ChildItem -DnsName $siteName Cert:\LocalMachine\My
        if ($null -eq $certificate) {
            Write-Host "Importing the $siteName certificate..."
            $certificate = @(Import-PfxCertificate `
                -FilePath "C:\vagrant\shared\beats-example-ca\$siteName-key.p12" `
                -CertStoreLocation Cert:\LocalMachine\My `
                -Password $null `
                -Exportable)[0]
        }
        Write-Host "Creating the $siteName site..."
        $siteDirectory = "C:\inetpub\$siteName"
        if (!(Test-Path $siteDirectory)) {
            mkdir $siteDirectory | Out-Null
        }
        $website = New-Website `
            -Name $siteName `
            -HostHeader $uri.Authority `
            -PhysicalPath $siteDirectory `
            -ApplicationPool $siteName `
            -Port $uri.Port `
            -Ssl `
            -SslFlags 1
        $binding = Get-WebBinding `
            -Name $siteName `
            -HostHeader $siteName `
            -Port $uri.Port
        if ($binding.certificateHash -eq '') {
            $binding.AddSslCertificate($certificate.Thumbprint, 'My')
        }
    }

    Write-Host "Adding rewrite rules to $siteName..."
    Clear-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
        -Filter 'system.webServer/rewrite/rules/rule'
    $_.Value | ForEach-Object {
        $data = $_ -split '\s+'
        $pattern = $data[0]
        $url = $data[1]
        $ruleName = $pattern -replace '[^A-Za-z0-9]','_'
        Write-Host "Adding rewrite rule pattern $pattern => $url to $siteName..."
        # NB this modifies the application web.config file.
        Add-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -Filter 'system.webServer/rewrite/rules' `
            -Name '.' `
            -Value @{name=$RuleName;patternSyntax='Wildcard';stopProcessing='true'}
        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/match" `
            -Name 'url' `
            -Value $pattern
        Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST/$siteName" `
            -Filter "system.webServer/rewrite/rules/rule[@name='$ruleName']/action" `
            -Name '.' `
            -Value @{type='Rewrite';url=$url}
    }
}

Write-Host 'Restarting IIS (and dependent services)...'
Restart-Service w3svc -Force
