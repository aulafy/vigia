& {
    # Enrol this Windows computer with Vigía, collect its inventory, and push it signed. Windows PowerShell 5.1+.
    #
    # Install (run as Administrator):
    #   $env:VIGIA_URL='https://vigia.example.com'; $env:VIGIA_TOKEN='<token>'; irm https://vigia.example.com/agent/vigia-agent.ps1 | iex
    # Daily collection is installed as the SYSTEM scheduled task "Vigia inventory".
    # Dry run (no admin, install, or network): $env:VIGIA_DRYRUN='1'; .\vigia-agent.ps1
    # Uninstall: $env:VIGIA_UNINSTALL='1'; .\vigia-agent.ps1   or   .\vigia-agent.ps1 -Uninstall
    $ErrorActionPreference = 'Stop'

    $installDir = 'C:\ProgramData\Vigia'
    $scriptPath = Join-Path $installDir 'vigia-agent.ps1'
    $configPath = Join-Path $installDir 'agent.json'
    $logPath = Join-Path $installDir 'last.log'
    $taskName = 'Vigia inventory'

    function Format-UtcDate($value) {
        ([datetime]$value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    function Get-ServerError($record) {
        $text = $null
        if ($record.ErrorDetails -and $record.ErrorDetails.Message) {
            $text = [string]$record.ErrorDetails.Message
        }
        if (-not $text -and $record.Exception.Response) {
            try {
                $stream = $record.Exception.Response.GetResponseStream()
                if ($stream) {
                    $reader = New-Object System.IO.StreamReader($stream)
                    try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
                }
            } catch { }
        }
        if ($text) {
            try {
                $parsed = $text | ConvertFrom-Json
                if ($parsed.error) { return [string]$parsed.error }
            } catch { }
            return $text.Trim()
        }
        return $record.Exception.Message
    }

    function New-InventoryJson {
        $parts = New-Object 'System.Collections.Generic.List[object]'

        try {
            $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $displayVersion = [string]$cv.DisplayVersion
            if (-not $displayVersion) { $displayVersion = [string]$cv.ReleaseId }
            $parts.Add([ordered]@{
                kind = 'os'
                id = 'windows'
                productName = [string]$cv.ProductName
                displayVersion = $displayVersion
                build = [int]$cv.CurrentBuild
                ubr = [int]$cv.UBR
                edition = [string]$cv.EditionID
                installationType = [string]$cv.InstallationType
            })
        } catch { Write-Warning "OS inventory skipped: $($_.Exception.Message)" }

        $products = New-Object 'System.Collections.Generic.List[object]'
        $defenderAdded = $false
        try {
            $mp = Get-MpComputerStatus
            $signatureDate = $null
            if ($null -ne $mp.AntivirusSignatureLastUpdated) {
                $signatureDate = Format-UtcDate $mp.AntivirusSignatureLastUpdated
            }
            $products.Add([ordered]@{
                name = 'Microsoft Defender'
                enabled = [bool]($mp.AMServiceEnabled -and $mp.AntivirusEnabled)
                realTime = [bool]$mp.RealTimeProtectionEnabled
                upToDate = [bool]([int]$mp.AntivirusSignatureAge -le 7)
                signaturesAt = $signatureDate
                version = [string]$mp.AMProductVersion
            })
            $defenderAdded = $true
        } catch { }
        try {
            $otherProducts = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntiVirusProduct')
            foreach ($product in $otherProducts) {
                $name = [string]$product.displayName
                if ($defenderAdded -and $name -match 'Defender') { continue }
                $state = '{0:x6}' -f [int]$product.productState
                $enabled = $state.Substring(2, 2) -in @('10', '11')
                $products.Add([ordered]@{
                    name = $name
                    enabled = [bool]$enabled
                    realTime = [bool]$enabled
                    upToDate = [bool]($state.Substring(4, 2) -eq '00')
                    signaturesAt = $null
                    version = $null
                })
            }
        } catch { }
        $parts.Add([ordered]@{ kind = 'av'; products = [object[]]$products.ToArray() })

        try {
            $items = New-Object 'System.Collections.Generic.List[object]'
            $seen = @{}
            $uninstallPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            foreach ($entry in @(Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue)) {
                if (-not $entry.DisplayName -or [int]$entry.SystemComponent -eq 1 -or $entry.ParentKeyName) { continue }
                if ([string]$entry.ReleaseType -in @('Update', 'Hotfix', 'Security Update')) { continue }
                $name = ([string]$entry.DisplayName).Trim()
                $version = ([string]$entry.DisplayVersion).Trim()
                $publisher = ([string]$entry.Publisher).Trim()
                $key = $name + "`0" + $version
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                $items.Add([ordered]@{ name = $name; version = $version; publisher = $publisher })
                if ($items.Count -ge 3000) { break }
            }
            $parts.Add([ordered]@{ kind = 'software'; items = [object[]]$items.ToArray() })
        } catch { Write-Warning "Software inventory skipped: $($_.Exception.Message)" }

        try {
            $ports = New-Object 'System.Collections.Generic.List[object]'
            $seenPorts = @{}
            $processes = @{}
            foreach ($connection in @(Get-NetTCPConnection -State Listen)) {
                $key = 'tcp' + "`0" + [string]$connection.LocalAddress + "`0" + [string]$connection.LocalPort
                if ($seenPorts.ContainsKey($key)) { continue }
                $seenPorts[$key] = $true
                $pidKey = [string]$connection.OwningProcess
                if (-not $processes.ContainsKey($pidKey)) {
                    try { $processes[$pidKey] = [string](Get-Process -Id $connection.OwningProcess).ProcessName }
                    catch { $processes[$pidKey] = $null }
                }
                $ports.Add([ordered]@{
                    proto = 'tcp'
                    addr = [string]$connection.LocalAddress
                    port = [int]$connection.LocalPort
                    process = $processes[$pidKey]
                })
            }
            $parts.Add([ordered]@{ kind = 'listening'; ports = [object[]]$ports.ToArray() })
        } catch { Write-Warning "Listening-port inventory skipped: $($_.Exception.Message)" }

        try {
            $latest = $null
            $latestDate = $null
            foreach ($hotfix in @(Get-HotFix)) {
                if ($null -eq $hotfix.InstalledOn) { continue }
                try { $installed = [datetime]$hotfix.InstalledOn } catch { continue }
                if ($null -eq $latestDate -or $installed -gt $latestDate) {
                    $latest = $hotfix
                    $latestDate = $installed
                }
            }
            $lastInstalled = $null
            $hotfixId = $null
            if ($latest) {
                $lastInstalled = Format-UtcDate $latestDate
                $hotfixId = [string]$latest.HotFixID
            }
            $parts.Add([ordered]@{ kind = 'patches'; lastInstalled = $lastInstalled; id = $hotfixId })
        } catch { Write-Warning "Patch inventory skipped: $($_.Exception.Message)" }

        # Public address of this network (used by Vigía only when it cannot see it itself). VIGIA_IP_URL=off skips it.
        $ipUrl = 'https://api.ipify.org'
        if ($env:VIGIA_IP_URL) { $ipUrl = [string]$env:VIGIA_IP_URL }
        if ($ipUrl -ne 'off') {
            try {
                $publicIp = ([string](Invoke-RestMethod -Uri $ipUrl -TimeoutSec 5 -UseBasicParsing)).Trim()
                if ($publicIp -match '^[0-9A-Fa-f:.]{3,45}$') { $parts.Add([ordered]@{ kind = 'network'; publicIp = $publicIp }) }
            } catch { Write-Warning "Public address lookup skipped: $($_.Exception.Message)" }
        }

        $body = [ordered]@{
            host = [string]$env:COMPUTERNAME
            collectedAt = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            agent = 'ps1-1'
            parts = [object[]]$parts.ToArray()
        }
        $body | ConvertTo-Json -Depth 8 -Compress
    }

    function Write-LastResult([string]$message) {
        $message | Set-Content -LiteralPath $logPath -Encoding UTF8
        Write-Host $message
    }

    function Send-Inventory([string]$body) {
        if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
            throw 'Not installed: run the install line from the dashboard'
        }
        try { $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json }
        catch { throw "Cannot read agent configuration: $($_.Exception.Message)" }
        if (-not $config.url -or -not $config.asset -or -not $config.key) {
            throw 'Cannot read agent configuration: url, asset, or key is missing'
        }

        $url = ([string]$config.url).TrimEnd('/')
        $asset = [string]$config.asset
        $path = '/api/inventory/' + [Uri]::EscapeDataString($asset)
        $ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $messageBytes = [Text.Encoding]::UTF8.GetBytes(([string]$ts + '.' + $path + '.' + $body))
        $keyBytes = [Text.Encoding]::UTF8.GetBytes([string]$config.key)
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        try {
            $hmac.Key = $keyBytes
            $signature = -join ($hmac.ComputeHash($messageBytes) | ForEach-Object { $_.ToString('x2') })
        } finally { $hmac.Dispose() }

        $headers = @{
            'x-vigia-timestamp' = [string]$ts
            'x-vigia-signature' = $signature
        }
        try {
            $webResponse = Invoke-WebRequest -Uri ($url + $path) -Method Post -Headers $headers -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 120 -UseBasicParsing
            $response = $webResponse.Content | ConvertFrom-Json
            if (-not $response.ok) {
                $serverMessage = [string]$response.error
                if (-not $serverMessage) { $serverMessage = 'server rejected the inventory' }
                throw $serverMessage
            }
        } catch {
            $reason = Get-ServerError $_
            $line = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') + " error: $reason"
            Write-LastResult $line
            throw "Inventory failed: $reason"
        }

        $line = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') + ' inventory sent: ' + [string]$response.components + ' components'
        Write-LastResult $line
        foreach ($serverError in @($response.errors)) {
            if ($null -ne $serverError -and [string]$serverError) { Write-Warning "Server: $serverError" }
        }
        return $response
    }

    function Test-Administrator {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Install-Agent {
        if (-not (Test-Administrator)) { throw 'Run PowerShell as Administrator' }
        if (-not $env:VIGIA_URL) { throw 'VIGIA_URL is required' }

        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $url = ([string]$env:VIGIA_URL).TrimEnd('/')
        try { $uri = [Uri]$url } catch { throw "Invalid VIGIA_URL: $url" }
        if ($uri.Scheme -notin @('http', 'https') -or -not $uri.Host) { throw "Invalid VIGIA_URL: $url" }
        if ($uri.Scheme -eq 'http') {
            $hostName = $uri.Host
            $privateHost = $hostName -eq 'localhost' -or $hostName -match '^127\.' -or $hostName -match '^10\.' -or $hostName -match '^192\.168\.' -or $hostName -match '^172\.(1[6-9]|2[0-9]|3[01])\.'
            # over the Internet, plain HTTP would let anyone on the way swap the script this computer runs as SYSTEM
            if (-not $privateHost -and $env:VIGIA_INSECURE -ne '1') { throw 'VIGIA_URL uses plain HTTP outside your local network: use an https:// address (or VIGIA_INSECURE=1 at your own risk)' }
            Write-Warning 'VIGIA_URL uses HTTP; the key travels unencrypted'
        }

        # The task runs this folder's script as SYSTEM: a folder a normal user created beforehand (or a link) must not be trusted
        if (Test-Path -LiteralPath $installDir) {
            $existing = Get-Item -LiteralPath $installDir -Force
            if ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$installDir is a link: remove it and run the line again" }
        }
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        & icacls.exe $installDir '/setowner' '*S-1-5-32-544' '/T' '/C' | Out-Null
        & icacls.exe $installDir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '/T' '/C' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not restrict permissions on $installDir" }
        foreach ($item in @(Get-ChildItem -LiteralPath $installDir -Force)) { Remove-Item -LiteralPath $item.FullName -Recurse -Force }
        try {
            Invoke-WebRequest -Uri ($url + '/agent/vigia-agent.ps1') -UseBasicParsing -OutFile $scriptPath
        } catch { throw "Agent download failed: $(Get-ServerError $_)" }

        $machineGuid = [string](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $machineId = -join ($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid)) | ForEach-Object { $_.ToString('x2') })
        } finally { $sha256.Dispose() }
        $enrolmentBody = [ordered]@{
            token = [string]$env:VIGIA_TOKEN
            host = [string]$env:COMPUTERNAME
            machineId = $machineId
            platform = 'windows'
        } | ConvertTo-Json -Depth 4 -Compress
        try {
            $enrolmentWeb = Invoke-WebRequest -Uri ($url + '/api/enroll') -Method Post -ContentType 'application/json' -Body ([Text.Encoding]::UTF8.GetBytes($enrolmentBody)) -TimeoutSec 120 -UseBasicParsing
            $enrolment = $enrolmentWeb.Content | ConvertFrom-Json
        } catch { throw "Enrollment failed: $(Get-ServerError $_)" }
        if (-not $enrolment.ok -or -not $enrolment.asset -or -not $enrolment.key) {
            $reason = [string]$enrolment.error
            if (-not $reason) { $reason = 'invalid server response' }
            throw "Enrollment failed: $reason"
        }

        [ordered]@{ url = $url; asset = [string]$enrolment.asset; key = [string]$enrolment.key } |
            ConvertTo-Json -Depth 3 -Compress |
            Set-Content -LiteralPath $configPath -Encoding UTF8
        & icacls.exe $configPath '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not restrict permissions on $configPath" }

        $minute = Get-Random -Minimum 120 -Maximum 360
        $trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddMinutes($minute))
        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\ProgramData\Vigia\vigia-agent.ps1"'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

        $body = New-InventoryJson
        $response = Send-Inventory $body
        Write-Host ('Registered as ' + [string]$enrolment.asset + ' (client ' + [string]$enrolment.client + '). Inventory sent: ' + [string]$response.components + ' components.')
    }

    try {
        if ($env:VIGIA_DRYRUN -eq '1') {
            Write-Output (New-InventoryJson)
            return
        }

        $commandLineArgs = [Environment]::GetCommandLineArgs()
        if ($env:VIGIA_UNINSTALL -eq '1' -or $commandLineArgs -contains '-Uninstall') {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $installDir) { Remove-Item -LiteralPath $installDir -Recurse -Force }
            Write-Host 'Vigía agent uninstalled. Remove this computer from the dashboard too.'
            return
        }

        if ($null -ne $env:VIGIA_TOKEN -and $env:VIGIA_TOKEN.Length -gt 0) {
            Install-Agent
            return
        }

        $body = New-InventoryJson
        $null = Send-Inventory $body
    } catch {
        Write-Error $_.Exception.Message -ErrorAction Continue
        return
    }
}
