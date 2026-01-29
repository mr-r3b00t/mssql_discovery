<#
.SYNOPSIS
    MSSQL Security Audit Tool - Discovers SQL Servers and checks for dangerous configurations.

.DESCRIPTION
    1. Enumerates servers from Active Directory (or uses provided list)
    2. Discovers MSSQL instances
    3. Checks dangerous configurations (xp_cmdshell, CLR, etc.)
    4. Inventories databases, logins, and jobs

.EXAMPLE
    .\Invoke-MSSQLAudit.ps1 -Verbose
    .\Invoke-MSSQLAudit.ps1 -ServerList @("SQL01", "SQL02")
    .\Invoke-MSSQLAudit.ps1 -Credential (Get-Credential) -OutputPath "C:\Audits"
#>

[CmdletBinding()]
param(
    [string[]]$ServerList,
    [PSCredential]$Credential,
    [string]$OutputPath = ".",
    [int]$SQLPort = 1433,
    [int]$Timeout = 5
)

#region Utility Functions

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $colors = @{ Info = "Cyan"; Warning = "Yellow"; Error = "Red"; Success = "Green" }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $colors[$Level]
}

function Test-Port {
    param([string]$Computer, [int]$Port, [int]$Timeout = 3)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $result = $tcp.BeginConnect($Computer, $Port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne($Timeout * 1000, $false)
        if ($success) { $tcp.EndConnect($result) }
        $tcp.Close()
        return $success
    } catch { return $false }
}

function Invoke-SQL {
    param([string]$Server, [string]$Query, [PSCredential]$Credential, [string]$Database = "master")
    try {
        $cs = "Server=$Server;Database=$Database;Connection Timeout=10;"
        if ($Credential) {
            $cs += "User Id=$($Credential.UserName);Password=$($Credential.GetNetworkCredential().Password);"
        } else {
            $cs += "Integrated Security=True;"
        }
        $conn = New-Object System.Data.SqlClient.SqlConnection($cs)
        $conn.Open()
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $Query
        $cmd.CommandTimeout = 30
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($cmd)
        $ds = New-Object System.Data.DataSet
        $adapter.Fill($ds) | Out-Null
        $conn.Close()
        return $ds.Tables[0]
    } catch {
        Write-Verbose "SQL Error on $Server : $_"
        return $null
    }
}

#endregion

#region Discovery Functions

function Get-DomainServers {
    Write-Log "Querying Active Directory for servers..."
    $servers = @()
    
    try {
        # Try AD module first
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $computers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -Properties DNSHostName, OperatingSystem | 
                         Where-Object { $_.Enabled }
            foreach ($c in $computers) {
                $servers += [PSCustomObject]@{ Name = $c.DNSHostName; OS = $c.OperatingSystem }
            }
        }
    } catch {
        Write-Log "AD module failed, trying ADSI..." -Level Warning
    }
    
    # Fallback to ADSI
    if ($servers.Count -eq 0) {
        try {
            $searcher = New-Object DirectoryServices.DirectorySearcher
            $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*Server*))"
            $searcher.PageSize = 1000
            foreach ($r in $searcher.FindAll()) {
                $servers += [PSCustomObject]@{ 
                    Name = $r.Properties["dnshostname"][0]
                    OS = $r.Properties["operatingsystem"][0]
                }
            }
        } catch {
            Write-Log "ADSI query failed: $_" -Level Error
        }
    }
    
    Write-Log "Found $($servers.Count) servers" -Level Success
    return $servers
}

function Find-SQLInstances {
    param([string]$Computer, [int]$Port = 1433)
    
    $instances = @()
    
    # Check default port
    if (Test-Port -Computer $Computer -Port $Port) {
        $instances += [PSCustomObject]@{ Server = $Computer; Instance = "DEFAULT"; Port = $Port }
    }
    
    # Try SQL Browser (UDP 1434)
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = 3000
        $udp.Connect($Computer, 1434)
        $udp.Send([byte]0x02, 1) | Out-Null
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $response = [Text.Encoding]::ASCII.GetString($udp.Receive([ref]$ep))
        $udp.Close()
        
        # Parse instances
        if ($response -match "InstanceName;([^;]+).*?tcp;(\d+)") {
            $matches = [regex]::Matches($response, "InstanceName;([^;]+).*?tcp;(\d+)")
            foreach ($m in $matches) {
                $name = $m.Groups[1].Value
                $port = [int]$m.Groups[2].Value
                if (-not ($instances | Where-Object { $_.Port -eq $port })) {
                    $instances += [PSCustomObject]@{ Server = $Computer; Instance = $name; Port = $port }
                }
            }
        }
    } catch { }
    
    return $instances
}

#endregion

#region Audit Functions

function Get-SQLSecurityConfig {
    param([string]$ServerInstance, [PSCredential]$Credential)
    
    $result = [ordered]@{
        ServerInstance = $ServerInstance
        Connected = $false
        Version = $null
        Edition = $null
        
        # Dangerous Settings
        XPCmdShell = $null
        CLREnabled = $null
        OLEAutomation = $null
        ExternalScripts = $null
        AdHocQueries = $null
        
        # Account Security
        SAEnabled = $null
        SARenamed = $null
        
        # Findings
        TrustworthyDBs = @()
        LinkedServers = @()
    }
    
    # Get server info
    $info = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query @"
SELECT SERVERPROPERTY('ProductVersion') AS Version,
       SERVERPROPERTY('Edition') AS Edition,
       SYSTEM_USER AS CurrentUser,
       IS_SRVROLEMEMBER('sysadmin') AS IsSysAdmin
"@
    
    if (-not $info) { return [PSCustomObject]$result }
    
    $result.Connected = $true
    $result.Version = $info.Version
    $result.Edition = $info.Edition
    
    # Get configurations
    $configs = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query @"
SELECT name, CAST(value_in_use AS int) AS value
FROM sys.configurations
WHERE name IN ('xp_cmdshell','clr enabled','Ole Automation Procedures',
               'external scripts enabled','Ad Hoc Distributed Queries')
"@
    
    if ($configs) {
        foreach ($c in $configs) {
            switch ($c.name) {
                'xp_cmdshell' { $result.XPCmdShell = ($c.value -eq 1) }
                'clr enabled' { $result.CLREnabled = ($c.value -eq 1) }
                'Ole Automation Procedures' { $result.OLEAutomation = ($c.value -eq 1) }
                'external scripts enabled' { $result.ExternalScripts = ($c.value -eq 1) }
                'Ad Hoc Distributed Queries' { $result.AdHocQueries = ($c.value -eq 1) }
            }
        }
    }
    
    # Check SA account
    $sa = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query @"
SELECT name, is_disabled FROM sys.sql_logins WHERE principal_id = 1
"@
    if ($sa) {
        $result.SAEnabled = -not $sa.is_disabled
        $result.SARenamed = ($sa.name -ne 'sa')
    }
    
    # Get trustworthy databases
    $trustworthy = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query @"
SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name NOT IN ('msdb')
"@
    if ($trustworthy) { $result.TrustworthyDBs = @($trustworthy.name) }
    
    # Get linked servers
    $linked = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query @"
SELECT name, data_source FROM sys.servers WHERE is_linked = 1
"@
    if ($linked) { $result.LinkedServers = @($linked | ForEach-Object { "$($_.name) -> $($_.data_source)" }) }
    
    return [PSCustomObject]$result
}

function Get-SQLDatabases {
    param([string]$ServerInstance, [PSCredential]$Credential)
    
    $query = @"
SELECT 
    d.name AS DatabaseName,
    d.state_desc AS State,
    d.recovery_model_desc AS RecoveryModel,
    d.compatibility_level AS CompatLevel,
    SUSER_SNAME(d.owner_sid) AS Owner,
    d.is_encrypted AS Encrypted,
    d.is_trustworthy_on AS Trustworthy,
    (SELECT SUM(size * 8.0 / 1024) FROM sys.master_files WHERE database_id = d.database_id) AS SizeMB,
    (SELECT COUNT(*) FROM sys.master_files WHERE database_id = d.database_id AND type = 0) AS DataFiles,
    (SELECT COUNT(*) FROM sys.master_files WHERE database_id = d.database_id AND type = 1) AS LogFiles
FROM sys.databases d
ORDER BY d.name
"@
    
    $dbs = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query $query
    if ($dbs) {
        return $dbs | ForEach-Object {
            [PSCustomObject]@{
                ServerInstance = $ServerInstance
                Database = $_.DatabaseName
                State = $_.State
                RecoveryModel = $_.RecoveryModel
                CompatLevel = $_.CompatLevel
                Owner = $_.Owner
                SizeMB = [math]::Round($_.SizeMB, 2)
                DataFiles = $_.DataFiles
                LogFiles = $_.LogFiles
                Encrypted = [bool]$_.Encrypted
                Trustworthy = [bool]$_.Trustworthy
            }
        }
    }
    return @()
}

function Get-SQLLogins {
    param([string]$ServerInstance, [PSCredential]$Credential)
    
    $query = @"
SELECT 
    sp.name AS LoginName,
    sp.type_desc AS LoginType,
    sp.is_disabled AS Disabled,
    sp.create_date AS Created,
    sp.default_database_name AS DefaultDB,
    (SELECT STRING_AGG(r.name, ', ') FROM sys.server_role_members rm 
     JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id 
     WHERE rm.member_principal_id = sp.principal_id) AS ServerRoles
FROM sys.server_principals sp
WHERE sp.type IN ('S','U','G') AND sp.name NOT LIKE '##%' AND sp.name NOT LIKE 'NT %'
ORDER BY sp.name
"@
    
    $logins = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query $query
    if ($logins) {
        return $logins | ForEach-Object {
            [PSCustomObject]@{
                ServerInstance = $ServerInstance
                Login = $_.LoginName
                Type = $_.LoginType
                Disabled = [bool]$_.Disabled
                DefaultDB = $_.DefaultDB
                ServerRoles = $_.ServerRoles
                Created = $_.Created
            }
        }
    }
    return @()
}

function Get-SQLJobs {
    param([string]$ServerInstance, [PSCredential]$Credential)
    
    $query = @"
SELECT 
    j.name AS JobName,
    j.enabled AS Enabled,
    SUSER_SNAME(j.owner_sid) AS Owner,
    c.name AS Category,
    (SELECT COUNT(*) FROM msdb.dbo.sysjobsteps WHERE job_id = j.job_id) AS Steps,
    CASE h.run_status WHEN 0 THEN 'Failed' WHEN 1 THEN 'Succeeded' WHEN 2 THEN 'Retry' 
         WHEN 3 THEN 'Canceled' ELSE 'Unknown' END AS LastStatus
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.syscategories c ON j.category_id = c.category_id
OUTER APPLY (SELECT TOP 1 run_status FROM msdb.dbo.sysjobhistory 
             WHERE job_id = j.job_id AND step_id = 0 ORDER BY instance_id DESC) h
ORDER BY j.name
"@
    
    $jobs = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query $query -Database "msdb"
    if ($jobs) {
        return $jobs | ForEach-Object {
            [PSCustomObject]@{
                ServerInstance = $ServerInstance
                JobName = $_.JobName
                Enabled = [bool]$_.Enabled
                Owner = $_.Owner
                Category = $_.Category
                Steps = $_.Steps
                LastStatus = $_.LastStatus
            }
        }
    }
    return @()
}

function Get-SQLBackupStatus {
    param([string]$ServerInstance, [PSCredential]$Credential)
    
    $query = @"
SELECT 
    d.name AS DatabaseName,
    d.recovery_model_desc AS RecoveryModel,
    MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END) AS LastFull,
    MAX(CASE WHEN bs.type = 'L' THEN bs.backup_finish_date END) AS LastLog,
    DATEDIFF(DAY, MAX(CASE WHEN bs.type = 'D' THEN bs.backup_finish_date END), GETDATE()) AS DaysSinceFull
FROM sys.databases d
LEFT JOIN msdb.dbo.backupset bs ON d.name = bs.database_name
WHERE d.database_id > 4
GROUP BY d.name, d.recovery_model_desc
ORDER BY d.name
"@
    
    $backups = Invoke-SQL -Server $ServerInstance -Credential $Credential -Query $query
    if ($backups) {
        return $backups | ForEach-Object {
            [PSCustomObject]@{
                ServerInstance = $ServerInstance
                Database = $_.DatabaseName
                RecoveryModel = $_.RecoveryModel
                LastFullBackup = $_.LastFull
                LastLogBackup = $_.LastLog
                DaysSinceFull = $_.DaysSinceFull
                Status = if ($null -eq $_.LastFull) { "NEVER" } elseif ($_.DaysSinceFull -gt 7) { "WARNING" } else { "OK" }
            }
        }
    }
    return @()
}

#endregion

#region Main Script

Write-Log "=== MSSQL Security Audit Tool ===" -Level Success

# Get servers to scan
$servers = @()
if ($ServerList) {
    $servers = $ServerList | ForEach-Object { [PSCustomObject]@{ Name = $_; OS = "Manual" } }
    Write-Log "Using provided list of $($servers.Count) servers"
} else {
    $servers = Get-DomainServers
}

if ($servers.Count -eq 0) {
    Write-Log "No servers to scan!" -Level Error
    return
}

# Initialize results
$allResults = @{
    Security = @()
    Databases = @()
    Logins = @()
    Jobs = @()
    Backups = @()
}

$sqlCount = 0

# Scan each server
foreach ($server in $servers) {
    $serverName = $server.Name
    if (-not $serverName) { continue }
    
    Write-Log "Scanning $serverName..."
    
    # Check if reachable
    if (-not (Test-Connection -ComputerName $serverName -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        Write-Log "  Not reachable, skipping" -Level Warning
        continue
    }
    
    # Find SQL instances
    $instances = Find-SQLInstances -Computer $serverName -Port $SQLPort
    if ($instances.Count -eq 0) {
        Write-Verbose "  No SQL instances found"
        continue
    }
    
    Write-Log "  Found $($instances.Count) SQL instance(s)" -Level Success
    $sqlCount++
    
    foreach ($inst in $instances) {
        $connStr = if ($inst.Port -eq 1433 -and $inst.Instance -eq "DEFAULT") { 
            $serverName 
        } else { 
            "$serverName,$($inst.Port)" 
        }
        
        Write-Log "    Auditing: $connStr"
        
        # Security config
        $security = Get-SQLSecurityConfig -ServerInstance $connStr -Credential $Credential
        if ($security.Connected) {
            $allResults.Security += $security
            
            # Show critical findings
            if ($security.XPCmdShell) { Write-Log "      [CRITICAL] xp_cmdshell ENABLED!" -Level Error }
            if ($security.CLREnabled) { Write-Log "      [HIGH] CLR enabled" -Level Warning }
            if ($security.SAEnabled -and -not $security.SARenamed) { Write-Log "      [HIGH] SA account enabled & not renamed" -Level Warning }
            if ($security.TrustworthyDBs.Count -gt 0) { Write-Log "      [HIGH] Trustworthy DBs: $($security.TrustworthyDBs -join ', ')" -Level Warning }
            
            # Inventory
            $allResults.Databases += Get-SQLDatabases -ServerInstance $connStr -Credential $Credential
            $allResults.Logins += Get-SQLLogins -ServerInstance $connStr -Credential $Credential
            $allResults.Jobs += Get-SQLJobs -ServerInstance $connStr -Credential $Credential
            $allResults.Backups += Get-SQLBackupStatus -ServerInstance $connStr -Credential $Credential
        } else {
            Write-Log "      Connection failed" -Level Warning
        }
    }
}

# Export results
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Log "Exporting results..."

if ($allResults.Security.Count -gt 0) {
    $allResults.Security | Export-Csv "$OutputPath\SQL_Security_$timestamp.csv" -NoTypeInformation
}
if ($allResults.Databases.Count -gt 0) {
    $allResults.Databases | Export-Csv "$OutputPath\SQL_Databases_$timestamp.csv" -NoTypeInformation
}
if ($allResults.Logins.Count -gt 0) {
    $allResults.Logins | Export-Csv "$OutputPath\SQL_Logins_$timestamp.csv" -NoTypeInformation
}
if ($allResults.Jobs.Count -gt 0) {
    $allResults.Jobs | Export-Csv "$OutputPath\SQL_Jobs_$timestamp.csv" -NoTypeInformation
}
if ($allResults.Backups.Count -gt 0) {
    $allResults.Backups | Export-Csv "$OutputPath\SQL_Backups_$timestamp.csv" -NoTypeInformation
}

# Summary
Write-Host ""
Write-Log "=== SUMMARY ===" -Level Success
Write-Host "  Servers Scanned:    $($servers.Count)"
Write-Host "  SQL Servers Found:  $sqlCount"
Write-Host "  Databases:          $($allResults.Databases.Count)"
Write-Host "  Logins:             $($allResults.Logins.Count)"
Write-Host "  Jobs:               $($allResults.Jobs.Count)"
Write-Host ""

# Security summary
$critical = @($allResults.Security | Where-Object { $_.XPCmdShell -eq $true }).Count
$high = @($allResults.Security | Where-Object { $_.CLREnabled -eq $true -or $_.OLEAutomation -eq $true -or ($_.SAEnabled -eq $true -and $_.SARenamed -eq $false) -or $_.TrustworthyDBs.Count -gt 0 }).Count
Write-Host "  Critical Issues:    $critical" -ForegroundColor $(if ($critical -gt 0) { "Red" } else { "Green" })
Write-Host "  High Risk Issues:   $high" -ForegroundColor $(if ($high -gt 0) { "Yellow" } else { "Green" })

Write-Log "Audit complete!" -Level Success

return $allResults

#endregion
