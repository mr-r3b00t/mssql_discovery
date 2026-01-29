<#
.SYNOPSIS
    MSSQL Security Audit Tool - Discovers SQL Servers and checks for dangerous configurations.

.DESCRIPTION
    1. Interactive menu for easy operation (or use parameters for automation)
    2. Enumerates servers from Active Directory (or uses provided list)
    3. Discovers MSSQL instances
    4. Checks dangerous configurations (xp_cmdshell, CLR, etc.)
    5. Inventories databases, logins, and jobs
    6. Generates HTML report with risk explanations

.EXAMPLE
    .\Invoke-MSSQLAudit.ps1
    Launches interactive menu to choose scan mode

.EXAMPLE
    .\Invoke-MSSQLAudit.ps1 -ServerList @("SQL01", "SQL02")
    Directly audits specified servers (no menu)

.EXAMPLE
    .\Invoke-MSSQLAudit.ps1 -Credential (Get-Credential) -OutputPath "C:\Audits"
    Scans domain with SQL authentication
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
    
    # Use FOR XML PATH for compatibility with SQL 2016 and earlier (STRING_AGG is 2017+)
    $query = @"
SELECT 
    sp.name AS LoginName,
    sp.type_desc AS LoginType,
    sp.is_disabled AS Disabled,
    sp.create_date AS Created,
    sp.default_database_name AS DefaultDB,
    STUFF((SELECT ', ' + r.name 
           FROM sys.server_role_members rm 
           JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id 
           WHERE rm.member_principal_id = sp.principal_id
           FOR XML PATH('')), 1, 2, '') AS ServerRoles
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

function Show-Menu {
    Clear-Host
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "       MSSQL Security Audit Tool" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Scan entire domain for SQL Servers"
    Write-Host "  [2] Audit a single server"
    Write-Host "  [3] Audit multiple servers (comma-separated)"
    Write-Host "  [Q] Quit"
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
}

function Get-UserChoice {
    $servers = @()
    
    while ($true) {
        Show-Menu
        $selection = Read-Host "Select an option"
        
        switch ($selection.ToUpper()) {
            "1" {
                Write-Host ""
                Write-Host "Will scan domain for SQL Servers..." -ForegroundColor Yellow
                return @{ Mode = "Domain"; Servers = @() }
            }
            "2" {
                Write-Host ""
                $server = Read-Host "Enter server name or IP"
                if ([string]::IsNullOrWhiteSpace($server)) {
                    Write-Host "No server specified. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                return @{ Mode = "Single"; Servers = @($server.Trim()) }
            }
            "3" {
                Write-Host ""
                Write-Host "Enter server names separated by commas"
                Write-Host "Example: SQL01, SQL02, SQL03" -ForegroundColor Gray
                $serverInput = Read-Host "Servers"
                if ([string]::IsNullOrWhiteSpace($serverInput)) {
                    Write-Host "No servers specified. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                $serverList = $serverInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
                if ($serverList.Count -eq 0) {
                    Write-Host "No valid servers specified. Please try again." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }
                return @{ Mode = "Multiple"; Servers = $serverList }
            }
            "Q" {
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit
            }
            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Determine mode of operation
$interactiveMode = $false

if (-not $ServerList -and -not $PSBoundParameters.ContainsKey('ServerList')) {
    # No servers specified via parameter - show interactive menu
    $userChoice = Get-UserChoice
    $interactiveMode = $true
    
    if ($userChoice.Mode -eq "Domain") {
        $ServerList = $null  # Will trigger AD enumeration
    } else {
        $ServerList = $userChoice.Servers
    }
    
    # Ask about credentials
    Write-Host ""
    $useWinAuth = Read-Host "Use Windows Authentication? [Y/n]"
    if ($useWinAuth -eq 'n' -or $useWinAuth -eq 'N') {
        Write-Host "Enter SQL credentials:" -ForegroundColor Yellow
        $Credential = Get-Credential -Message "SQL Server Authentication"
    }
    
    # Ask about output path
    Write-Host ""
    $customPath = Read-Host "Output path (press Enter for current directory)"
    if (-not [string]::IsNullOrWhiteSpace($customPath)) {
        $OutputPath = $customPath
    }
    
    Write-Host ""
}

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

# Generate HTML Report
$criticalCount = @($allResults.Security | Where-Object { $_.XPCmdShell -eq $true }).Count
$highCount = @($allResults.Security | Where-Object { $_.CLREnabled -eq $true -or $_.OLEAutomation -eq $true -or $_.ExternalScripts -eq $true -or ($_.SAEnabled -eq $true -and $_.SARenamed -eq $false) -or $_.TrustworthyDBs.Count -gt 0 }).Count
$backupWarnings = @($allResults.Backups | Where-Object { $_.Status -ne "OK" }).Count

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>MSSQL Security Audit Report</title>
    <style>
        body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .summary { display: flex; gap: 15px; flex-wrap: wrap; margin: 20px 0; }
        .card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); min-width: 150px; text-align: center; }
        .card h3 { margin: 0 0 10px 0; font-size: 2em; }
        .card p { margin: 0; color: #666; }
        .critical { border-left: 4px solid #e74c3c; }
        .critical h3 { color: #e74c3c; }
        .high { border-left: 4px solid #e67e22; }
        .high h3 { color: #e67e22; }
        .warning { border-left: 4px solid #f1c40f; }
        .warning h3 { color: #f1c40f; }
        .ok { border-left: 4px solid #27ae60; }
        .ok h3 { color: #27ae60; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th { background: #3498db; color: #fff; padding: 12px; text-align: left; }
        td { border: 1px solid #ddd; padding: 10px; }
        tr:nth-child(even) { background: #f9f9f9; }
        tr:hover { background: #f5f5f5; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.85em; font-weight: bold; background: #ecf0f1; color: #333; }
        .badge-critical { background: #e74c3c; color: #fff; }
        .badge-high { background: #e67e22; color: #fff; }
        .badge-warning { background: #f1c40f; color: #333; }
        .badge-ok { background: #27ae60; color: #fff; }
        .badge-disabled { background: #95a5a6; color: #fff; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
        .risk-guide { display: grid; gap: 15px; margin: 20px 0; }
        .risk-item { background: #fff; padding: 15px 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .risk-item h4 { margin: 0 0 10px 0; color: #2c3e50; }
        .risk-item p { margin: 8px 0; line-height: 1.5; color: #444; }
        .risk-item code { background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-family: Consolas, monospace; font-size: 0.9em; }
        .risk-item.critical { border-left: 4px solid #e74c3c; }
        .risk-item.high { border-left: 4px solid #e67e22; }
        .risk-item.warning { border-left: 4px solid #f1c40f; }
        .risk-item.info { border-left: 4px solid #3498db; }
        .nav { background: #2c3e50; padding: 12px 20px; margin: -20px -20px 20px -20px; }
        .nav a { color: #fff; margin-right: 20px; text-decoration: none; font-weight: 500; }
        .nav a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="nav">
        <a href="#summary">Summary</a>
        <a href="#risks">Risk Guide</a>
        <a href="#security">Security Config</a>
        <a href="#databases">Databases</a>
        <a href="#logins">Logins</a>
        <a href="#jobs">Jobs</a>
        <a href="#backups">Backups</a>
    </div>
    <h1>MSSQL Security Audit Report</h1>
    <p class="timestamp">Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <h2 id="summary">Executive Summary</h2>
    <div class="summary">
        <div class="card ok"><h3>$($servers.Count)</h3><p>Servers Scanned</p></div>
        <div class="card ok"><h3>$sqlCount</h3><p>SQL Servers Found</p></div>
        <div class="card ok"><h3>$($allResults.Databases.Count)</h3><p>Databases</p></div>
        <div class="card $(if($criticalCount -gt 0){'critical'}else{'ok'})"><h3>$criticalCount</h3><p>Critical Issues</p></div>
        <div class="card $(if($highCount -gt 0){'high'}else{'ok'})"><h3>$highCount</h3><p>High Risk Issues</p></div>
        <div class="card $(if($backupWarnings -gt 0){'warning'}else{'ok'})"><h3>$backupWarnings</h3><p>Backup Warnings</p></div>
    </div>

    <h2 id="risks">Risk Reference Guide</h2>
    <div class="risk-guide">
        <div class="risk-item critical">
            <h4>xp_cmdshell <span class="badge badge-critical">CRITICAL</span></h4>
            <p><strong>What it is:</strong> A SQL Server extended stored procedure that allows execution of operating system commands directly from T-SQL.</p>
            <p><strong>Why it's dangerous:</strong> If an attacker gains SQL access (via SQL injection or compromised credentials), they can execute ANY Windows command with the permissions of the SQL Server service account. This typically means SYSTEM-level access, allowing them to create users, install malware, pivot to other systems, or exfiltrate data.</p>
            <p><strong>Remediation:</strong> <code>EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;</code></p>
            <p><strong>If needed:</strong> Use SQL Agent jobs or SSIS packages instead. If absolutely required, restrict EXECUTE permission to specific logins and audit all usage.</p>
        </div>

        <div class="risk-item high">
            <h4>CLR Enabled <span class="badge badge-high">HIGH</span></h4>
            <p><strong>What it is:</strong> Common Language Runtime integration allows .NET assemblies to run inside SQL Server.</p>
            <p><strong>Why it's dangerous:</strong> Attackers can load malicious .NET code that bypasses SQL Server security. UNSAFE assemblies can access the file system, registry, network, and execute arbitrary code. Even SAFE assemblies can be exploited in combination with other vulnerabilities.</p>
            <p><strong>Remediation:</strong> <code>EXEC sp_configure 'clr enabled', 0; RECONFIGURE;</code></p>
            <p><strong>If needed:</strong> Use only SAFE assemblies, require assembly signing, enable "clr strict security" (SQL 2017+), and audit all deployed assemblies.</p>
        </div>

        <div class="risk-item high">
            <h4>OLE Automation Procedures <span class="badge badge-high">HIGH</span></h4>
            <p><strong>What it is:</strong> Enables creation of OLE automation objects (COM objects) within T-SQL using sp_OACreate, sp_OAMethod, etc.</p>
            <p><strong>Why it's dangerous:</strong> Allows instantiation of dangerous COM objects like WScript.Shell, Scripting.FileSystemObject, or MSXML2.ServerXMLHTTP. Attackers can read/write files, execute commands, or make network requests from the SQL Server.</p>
            <p><strong>Remediation:</strong> <code>EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;</code></p>
            <p><strong>If needed:</strong> Consider CLR procedures as a more securable alternative, or use external processes triggered by SQL Agent.</p>
        </div>

        <div class="risk-item high">
            <h4>External Scripts Enabled <span class="badge badge-high">HIGH</span></h4>
            <p><strong>What it is:</strong> Allows execution of external scripts in R, Python, or Java through sp_execute_external_script.</p>
            <p><strong>Why it's dangerous:</strong> External scripts run outside the SQL Server process and can access the file system, network, and execute arbitrary code. Python/R have extensive libraries for system access, network operations, and code execution.</p>
            <p><strong>Remediation:</strong> <code>EXEC sp_configure 'external scripts enabled', 0; RECONFIGURE;</code></p>
            <p><strong>If needed:</strong> Restrict EXECUTE permissions on sp_execute_external_script, use resource governance, and audit all script execution.</p>
        </div>

        <div class="risk-item high">
            <h4>SA Account Enabled & Not Renamed <span class="badge badge-high">HIGH</span></h4>
            <p><strong>What it is:</strong> The 'sa' (system administrator) account is the built-in SQL Server superuser with unrestricted access.</p>
            <p><strong>Why it's dangerous:</strong> The 'sa' account is the #1 target for brute force attacks because every SQL Server has it. If compromised, attackers have complete control. Many legacy applications hardcode 'sa' credentials.</p>
            <p><strong>Remediation:</strong> <code>ALTER LOGIN sa DISABLE;</code> or <code>ALTER LOGIN sa WITH NAME = [SomeOtherName];</code></p>
            <p><strong>Best practice:</strong> Disable sa entirely. Create named sysadmin accounts for administrators with strong passwords and audit their usage.</p>
        </div>

        <div class="risk-item high">
            <h4>Trustworthy Database <span class="badge badge-high">HIGH</span></h4>
            <p><strong>What it is:</strong> The TRUSTWORTHY property allows database objects to access resources outside the database with elevated privileges.</p>
            <p><strong>Why it's dangerous:</strong> If a database is owned by a sysadmin and marked TRUSTWORTHY, any user who can create procedures in that database can escalate to sysadmin. This is a well-known privilege escalation path.</p>
            <p><strong>Remediation:</strong> <code>ALTER DATABASE [DbName] SET TRUSTWORTHY OFF;</code></p>
            <p><strong>If needed:</strong> Change database owner to a non-sysadmin account, or use code signing with certificates instead.</p>
        </div>

        <div class="risk-item high">
            <h4>Linked Servers <span class="badge badge-high">HIGH</span></h4>
            <p><strong>What it is:</strong> Connections to other SQL Servers or data sources that allow distributed queries.</p>
            <p><strong>Why it's dangerous:</strong> Linked servers often store credentials and can be used to pivot to other systems. If configured with sysadmin mappings or "be made using the login's current security context," an attacker can leverage them to compromise additional servers.</p>
            <p><strong>Remediation:</strong> Review all linked servers: <code>SELECT * FROM sys.servers WHERE is_linked = 1</code>. Remove unnecessary links. Use least-privilege accounts for required links.</p>
        </div>

        <div class="risk-item warning">
            <h4>Ad Hoc Distributed Queries <span class="badge badge-warning">MEDIUM</span></h4>
            <p><strong>What it is:</strong> Allows OPENROWSET and OPENDATASOURCE functions to access remote data sources without predefined linked servers.</p>
            <p><strong>Why it's dangerous:</strong> Attackers can use these functions to connect to attacker-controlled servers (credential relay attacks), read local files, or access other databases without needing linked server configuration.</p>
            <p><strong>Remediation:</strong> <code>EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;</code></p>
        </div>

        <div class="risk-item warning">
            <h4>Missing/Old Backups <span class="badge badge-warning">MEDIUM</span></h4>
            <p><strong>What it is:</strong> Databases without recent full backups or transaction log backups.</p>
            <p><strong>Why it's dangerous:</strong> Without backups, ransomware attacks are devastating. Data loss from hardware failure, corruption, or accidental deletion is unrecoverable. Compliance requirements (HIPAA, SOX, GDPR) often mandate backup retention.</p>
            <p><strong>Remediation:</strong> Implement regular backup schedules. Full backups weekly minimum, differential daily, transaction logs every 15-60 minutes for FULL recovery model databases.</p>
        </div>

        <div class="risk-item info">
            <h4>Sysadmin Role Members <span class="badge badge-high">REVIEW</span></h4>
            <p><strong>What it is:</strong> Logins with the sysadmin fixed server role have unrestricted access to the entire SQL Server instance.</p>
            <p><strong>Why it matters:</strong> Every sysadmin is a potential compromise point. Service accounts, application accounts, and shared accounts with sysadmin rights are especially risky.</p>
            <p><strong>Best practice:</strong> Minimize sysadmin membership. Use Windows groups for administration. Audit who has sysadmin and why. Consider Just-In-Time access for DBAs.</p>
        </div>
    </div>

    <h2 id="security">Security Configuration</h2>
    <table>
        <tr><th>Server</th><th>Version</th><th>xp_cmdshell</th><th>CLR</th><th>OLE Auto</th><th>External Scripts</th><th>SA Enabled</th><th>SA Renamed</th><th>Trustworthy DBs</th><th>Linked Servers</th></tr>
"@

foreach ($s in $allResults.Security) {
    $xpBadge = if ($s.XPCmdShell) { '<span class="badge badge-critical">ENABLED</span>' } else { '<span class="badge badge-ok">Disabled</span>' }
    $clrBadge = if ($s.CLREnabled) { '<span class="badge badge-high">ENABLED</span>' } else { '<span class="badge badge-ok">Disabled</span>' }
    $oleBadge = if ($s.OLEAutomation) { '<span class="badge badge-high">ENABLED</span>' } else { '<span class="badge badge-ok">Disabled</span>' }
    $extBadge = if ($s.ExternalScripts) { '<span class="badge badge-high">ENABLED</span>' } else { '<span class="badge badge-ok">Disabled</span>' }
    $saBadge = if ($s.SAEnabled) { '<span class="badge badge-high">ENABLED</span>' } else { '<span class="badge badge-ok">Disabled</span>' }
    $saRenamed = if ($s.SARenamed) { '<span class="badge badge-ok">Yes</span>' } else { '<span class="badge badge-warning">No</span>' }
    
    # Format trustworthy DBs as individual badges
    if ($s.TrustworthyDBs.Count -gt 0) {
        $trustworthy = ($s.TrustworthyDBs | ForEach-Object { '<span class="badge badge-high">' + $_ + '</span>' }) -join " "
    } else {
        $trustworthy = "-"
    }
    
    # Format linked servers count with warning if present
    if ($s.LinkedServers.Count -gt 0) {
        $linked = '<span class="badge badge-warning">' + $s.LinkedServers.Count + ' linked</span>'
    } else {
        $linked = "-"
    }
    
    $html += "<tr><td>$($s.ServerInstance)</td><td>$($s.Version)</td><td>$xpBadge</td><td>$clrBadge</td><td>$oleBadge</td><td>$extBadge</td><td>$saBadge</td><td>$saRenamed</td><td>$trustworthy</td><td>$linked</td></tr>`n"
}

$html += @"
    </table>

    <h2 id="databases">Databases</h2>
    <table>
        <tr><th>Server</th><th>Database</th><th>State</th><th>Recovery Model</th><th>Size (MB)</th><th>Owner</th><th>Encrypted</th><th>Trustworthy</th></tr>
"@

foreach ($db in $allResults.Databases) {
    # State badge
    $stateBadge = switch ($db.State) {
        "ONLINE" { '<span class="badge badge-ok">ONLINE</span>' }
        "OFFLINE" { '<span class="badge badge-critical">OFFLINE</span>' }
        "RESTORING" { '<span class="badge badge-warning">RESTORING</span>' }
        "RECOVERING" { '<span class="badge badge-warning">RECOVERING</span>' }
        "SUSPECT" { '<span class="badge badge-critical">SUSPECT</span>' }
        "EMERGENCY" { '<span class="badge badge-critical">EMERGENCY</span>' }
        default { '<span class="badge">' + $db.State + '</span>' }
    }
    $encBadge = if ($db.Encrypted) { '<span class="badge badge-ok">Yes</span>' } else { "-" }
    $trustBadge = if ($db.Trustworthy) { '<span class="badge badge-high">Yes</span>' } else { "-" }
    $html += "<tr><td>$($db.ServerInstance)</td><td>$($db.Database)</td><td>$stateBadge</td><td>$($db.RecoveryModel)</td><td>$($db.SizeMB)</td><td>$($db.Owner)</td><td>$encBadge</td><td>$trustBadge</td></tr>`n"
}

$html += @"
    </table>

    <h2 id="logins">Logins</h2>
    <table>
        <tr><th>Server</th><th>Login</th><th>Type</th><th>Status</th><th>Server Roles</th><th>Default DB</th></tr>
"@

foreach ($l in $allResults.Logins) {
    $statusBadge = if ($l.Disabled) { '<span class="badge badge-disabled">Disabled</span>' } else { '<span class="badge badge-ok">Active</span>' }
    
    # Format roles - badge each one appropriately
    if ($l.ServerRoles) {
        $roleList = $l.ServerRoles -split ',\s*'
        $formattedRoles = foreach ($role in $roleList) {
            $role = $role.Trim()
            switch -Wildcard ($role) {
                "sysadmin" { '<span class="badge badge-critical">sysadmin</span>' }
                "securityadmin" { '<span class="badge badge-high">securityadmin</span>' }
                "serveradmin" { '<span class="badge badge-high">serveradmin</span>' }
                "dbcreator" { '<span class="badge badge-warning">dbcreator</span>' }
                "bulkadmin" { '<span class="badge badge-warning">bulkadmin</span>' }
                default { '<span class="badge">' + $role + '</span>' }
            }
        }
        $roles = $formattedRoles -join " "
    } else {
        $roles = "-"
    }
    
    $html += "<tr><td>$($l.ServerInstance)</td><td>$($l.Login)</td><td>$($l.Type)</td><td>$statusBadge</td><td>$roles</td><td>$($l.DefaultDB)</td></tr>`n"
}

$html += @"
    </table>

    <h2 id="jobs">SQL Agent Jobs</h2>
    <table>
        <tr><th>Server</th><th>Job Name</th><th>Enabled</th><th>Owner</th><th>Steps</th><th>Last Status</th></tr>
"@

foreach ($j in $allResults.Jobs) {
    $enabledBadge = if ($j.Enabled) { '<span class="badge badge-ok">Yes</span>' } else { '<span class="badge badge-disabled">No</span>' }
    $statusBadge = switch ($j.LastStatus) {
        "Succeeded" { '<span class="badge badge-ok">Succeeded</span>' }
        "Failed" { '<span class="badge badge-critical">Failed</span>' }
        "Retry" { '<span class="badge badge-warning">Retry</span>' }
        "Canceled" { '<span class="badge badge-warning">Canceled</span>' }
        "Unknown" { '<span class="badge badge-disabled">Unknown</span>' }
        default { '<span class="badge">' + $j.LastStatus + '</span>' }
    }
    $html += "<tr><td>$($j.ServerInstance)</td><td>$($j.JobName)</td><td>$enabledBadge</td><td>$($j.Owner)</td><td>$($j.Steps)</td><td>$statusBadge</td></tr>`n"
}

$html += @"
    </table>

    <h2 id="backups">Backup Status</h2>
    <table>
        <tr><th>Server</th><th>Database</th><th>Recovery Model</th><th>Last Full Backup</th><th>Last Log Backup</th><th>Days Since Full</th><th>Status</th></tr>
"@

foreach ($b in $allResults.Backups) {
    $statusBadge = switch ($b.Status) {
        "OK" { '<span class="badge badge-ok">OK</span>' }
        "WARNING" { '<span class="badge badge-warning">WARNING</span>' }
        "NEVER" { '<span class="badge badge-critical">NEVER</span>' }
        default { '<span class="badge">' + $b.Status + '</span>' }
    }
    $lastFull = if ($b.LastFullBackup) { $b.LastFullBackup.ToString("yyyy-MM-dd HH:mm") } else { '<span style="color:#999">Never</span>' }
    $lastLog = if ($b.LastLogBackup) { $b.LastLogBackup.ToString("yyyy-MM-dd HH:mm") } else { '<span style="color:#999">Never</span>' }
    $days = if ($null -eq $b.DaysSinceFull) { "-" } else { $b.DaysSinceFull }
    $html += "<tr><td>$($b.ServerInstance)</td><td>$($b.Database)</td><td>$($b.RecoveryModel)</td><td>$lastFull</td><td>$lastLog</td><td>$days</td><td>$statusBadge</td></tr>`n"
}

$html += @"
    </table>
</body>
</html>
"@

$htmlPath = "$OutputPath\SQL_Audit_Report_$timestamp.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Log "HTML Report: $htmlPath" -Level Success

# Summary
Write-Host ""
Write-Log "=== SUMMARY ===" -Level Success
Write-Host "  Servers Scanned:    $($servers.Count)"
Write-Host "  SQL Servers Found:  $sqlCount"
Write-Host "  Databases:          $($allResults.Databases.Count)"
Write-Host "  Logins:             $($allResults.Logins.Count)"
Write-Host "  Jobs:               $($allResults.Jobs.Count)"
Write-Host ""
Write-Host "  Critical Issues:    $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
Write-Host "  High Risk Issues:   $highCount" -ForegroundColor $(if ($highCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Backup Warnings:    $backupWarnings" -ForegroundColor $(if ($backupWarnings -gt 0) { "Yellow" } else { "Green" })
Write-Host ""
Write-Host "  Reports saved to:   $OutputPath" -ForegroundColor Cyan

Write-Log "Audit complete!" -Level Success

# Offer to open HTML report in interactive mode
if ($interactiveMode -and (Test-Path $htmlPath)) {
    Write-Host ""
    $openReport = Read-Host "Open HTML report in browser? [Y/n]"
    if ($openReport -ne 'n' -and $openReport -ne 'N') {
        Start-Process $htmlPath
    }
}

return $allResults

#endregion
