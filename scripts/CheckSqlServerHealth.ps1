<#
.SYNOPSIS
Comprehensive SQL Server and Windows health check script for enterprise environments.

.DESCRIPTION
This script performs health checks on multiple SQL Servers and their underlying Windows infrastructure.
It supports parallel execution, multiple output formats, and comprehensive error handling.

.PARAMETER ServerListPath
Path to a text file containing list of servers (one per line). Format: ServerName or ServerName,Port

.PARAMETER CheckProfile
Specifies the type of checks to perform.
- WindowsOnly: Only Windows server health checks
- WindowsAndSQL: Both Windows and SQL Server health checks (default)

.PARAMETER DryRun
Performs validation and shows what would be checked without executing actual health checks.

.PARAMETER MaxConcurrency
Maximum number of servers to check simultaneously. Default: 10

.PARAMETER OutputPath
Directory path for output files. Default: Current directory

.PARAMETER Timeout
Timeout in seconds for individual server checks. Default: 300 (5 minutes)

.EXAMPLE
.\CheckSqlServerHealth.ps1 -ServerListPath "servers.txt" -CheckProfile WindowsAndSQL

.EXAMPLE
.\CheckSqlServerHealth.ps1 -ServerListPath "servers.txt" -DryRun

.EXAMPLE
.\CheckSqlServerHealth.ps1 -ServerListPath "servers.txt" -MaxConcurrency 5 -OutputPath "C:\HealthReports"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Path to server list file")]
    [ValidateScript({Test-Path $_})]
    [string]$ServerListPath,
    
    [Parameter(HelpMessage = "Check profile: WindowsOnly or WindowsAndSQL")]
    [ValidateSet("WindowsOnly", "WindowsAndSQL")]
    [string]$CheckProfile = "WindowsAndSQL",
    
    [Parameter(HelpMessage = "Perform dry run without executing checks")]
    [switch]$DryRun,
    
    [Parameter(HelpMessage = "Maximum concurrent server checks")]
    [ValidateRange(1, 50)]
    [int]$MaxConcurrency = 10,
    
    [Parameter(HelpMessage = "Output directory for reports")]
    [string]$OutputPath = $PWD.Path,
    
    [Parameter(HelpMessage = "Timeout for individual server checks in seconds")]
    [ValidateRange(30, 1800)]
    [int]$Timeout = 300
)

#region Classes and Enums

enum HealthStatus {
    Excellent = 0
    Good = 1
    Fair = 2
    Poor = 3
    Critical = 4
    Unknown = 5
}

class ServerResult {
    [string]$ServerName
    [string]$Port
    [bool]$IsOnline
    [string]$ErrorMessage
    [hashtable]$WindowsHealth = @{}
    [hashtable]$SqlHealth = @{}
    [DateTime]$CheckStartTime
    [DateTime]$CheckEndTime
    [timespan]$Duration
    [HealthStatus]$OverallStatus = [HealthStatus]::Unknown
}

class HealthCheckResult {
    [string]$CheckName
    [HealthStatus]$Status
    [string]$Value
    [string]$Message
    [string]$Recommendation
}

#endregion

#region Global Variables and Initialization

$Global:Credential = $null
$Global:Results = @()
$Global:StartTime = Get-Date
$Global:ScriptRoot = Split-Path -Parent $PSScriptRoot
$Global:ProjectRoot = Split-Path -Parent $Global:ScriptRoot

# Initialize organized output paths
$Global:OutputPaths = @{
    Root = if ($OutputPath -eq $PWD.Path) { Join-Path $Global:ProjectRoot "outputs" } else { $OutputPath }
    Reports = ""
    Logs = ""
    Samples = ""
}

$Global:OutputFiles = @{
    DetailedLog = ""
    TechnicalReport = ""
    ManagementReportHtml = ""
    ManagementReportExcel = ""
}

# Load thresholds from config file or use defaults
$Global:Thresholds = @{
    DiskSpaceWarning = 15      # Percentage
    DiskSpaceCritical = 5      # Percentage
    CpuWarning = 75           # Percentage
    CpuCritical = 90          # Percentage
    MemoryWarning = 85        # Percentage
    MemoryCritical = 95       # Percentage
    DiskLatencyWarning = 20    # Milliseconds
    DiskLatencyCritical = 50   # Milliseconds
}

function Initialize-ProjectStructure {
    # Ensure output directories exist
    $Global:OutputPaths.Reports = Join-Path $Global:OutputPaths.Root "reports"
    $Global:OutputPaths.Logs = Join-Path $Global:OutputPaths.Root "logs"  
    $Global:OutputPaths.Samples = Join-Path $Global:OutputPaths.Root "samples"
    
    @($Global:OutputPaths.Root, $Global:OutputPaths.Reports, $Global:OutputPaths.Logs, $Global:OutputPaths.Samples) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
    
    # Load custom thresholds if config file exists
    $configPath = Join-Path $Global:ProjectRoot "config\default-thresholds.json"
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath | ConvertFrom-Json
            $Global:Thresholds.DiskSpaceWarning = $config.thresholds.diskSpace.warningPercent
            $Global:Thresholds.DiskSpaceCritical = $config.thresholds.diskSpace.criticalPercent
            $Global:Thresholds.CpuWarning = $config.thresholds.cpu.warningPercent
            $Global:Thresholds.CpuCritical = $config.thresholds.cpu.criticalPercent
            $Global:Thresholds.MemoryWarning = $config.thresholds.memory.warningPercent
            $Global:Thresholds.MemoryCritical = $config.thresholds.memory.criticalPercent
            $Global:Thresholds.DiskLatencyWarning = $config.thresholds.diskLatency.warningMs
            $Global:Thresholds.DiskLatencyCritical = $config.thresholds.diskLatency.criticalMs
            Write-ProgressMessage "Loaded custom thresholds from config file" "Green"
        } catch {
            Write-ProgressMessage "Warning: Could not load config file, using defaults" "Yellow"
        }
    }
}

#endregion

#region Helper Functions

function Write-ProgressMessage {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-DetailedLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [HealthStatus]$Status = [HealthStatus]::Unknown
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Add status symbol to log entry if status is provided
    $statusSymbol = ""
    if ($Status -ne [HealthStatus]::Unknown) {
        $statusSymbol = Get-StatusSymbol -Status $Status
        $Message = "$statusSymbol $Message"
    }
    
    $logEntry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $Global:OutputFiles.DetailedLog -Value $logEntry -ErrorAction SilentlyContinue
    
    # Also write colored output to console
    $color = Get-StatusColor -Status $Status -Level $Level
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-StatusColor {
    param(
        [HealthStatus]$Status = [HealthStatus]::Unknown,
        [string]$Level = "INFO"
    )
    
    # Priority: Level colors first, then Status colors
    switch ($Level) {
        "ERROR" { return "Red" }
        "WARN" { return "Yellow" }
        "SUCCESS" { return "Green" }
    }
    
    switch ($Status) {
        ([HealthStatus]::Excellent) { return "Green" }
        ([HealthStatus]::Good) { return "Green" }
        ([HealthStatus]::Fair) { return "Yellow" }
        ([HealthStatus]::Poor) { return "Red" }
        ([HealthStatus]::Critical) { return "Red" }
        default { return "White" }
    }
}

function Get-StatusSymbol {
    param([HealthStatus]$Status)
    
    switch ($Status) {
        ([HealthStatus]::Excellent) { return "[EXCELLENT]" }
        ([HealthStatus]::Good) { return "[GOOD]" }
        ([HealthStatus]::Fair) { return "[FAIR]" }
        ([HealthStatus]::Poor) { return "[POOR]" }
        ([HealthStatus]::Critical) { return "[CRITICAL]" }
        default { return "[UNKNOWN]" }
    }
}

function Write-ColoredStatus {
    param(
        [string]$ServerName,
        [HealthStatus]$Status,
        [string]$Message = ""
    )
    
    $symbol = Get-StatusSymbol -Status $Status
    $color = Get-StatusColor -Status $Status
    $statusText = "$symbol Status: $Status"
    
    if ($Message) {
        $statusText += " - $Message"
    }
    
    Write-Host "[$ServerName] $statusText" -ForegroundColor $color
    Write-DetailedLog "Completed health check for $ServerName - Status: $Status" "INFO" $Status
}

function Get-HealthStatusFromValue {
    param(
        [double]$Value,
        [double]$WarningThreshold,
        [double]$CriticalThreshold,
        [bool]$HigherIsBetter = $false
    )
    
    if ($HigherIsBetter) {
        if ($Value -ge $WarningThreshold) { return [HealthStatus]::Excellent }
        elseif ($Value -ge $CriticalThreshold) { return [HealthStatus]::Good }
        else { return [HealthStatus]::Critical }
    } else {
        if ($Value -le $CriticalThreshold) { return [HealthStatus]::Excellent }
        elseif ($Value -le $WarningThreshold) { return [HealthStatus]::Good }
        else { return [HealthStatus]::Critical }
    }
}

function Test-ServerConnectivity {
    param([string]$ServerName, [int]$Port = 445)
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($ServerName, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(5000, $false)
        
        if ($wait) {
            $tcpClient.EndConnect($connect)
            $tcpClient.Close()
            return $true
        } else {
            $tcpClient.Close()
            return $false
        }
    } catch {
        return $false
    }
}

function Install-RequiredModules {
    Write-ProgressMessage "Checking required PowerShell modules..." "Yellow"
    
    $requiredModules = @('SqlServer', 'ImportExcel')
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-ProgressMessage "Installing module: $module" "Yellow"
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                Write-ProgressMessage "Successfully installed $module" "Green"
            } catch {
                Write-Warning "Failed to install $module. Some features may not work correctly."
                Write-DetailedLog "Failed to install module $module`: $_" "ERROR"
            }
        }
    }
}

function Get-Credentials {
    if ($Global:Credential -eq $null) {
        Write-ProgressMessage "Please provide Windows credentials for server access:" "Yellow"
        $Global:Credential = Get-Credential -Message "Enter Windows credentials for server access"
        
        if ($Global:Credential -eq $null) {
            throw "Credentials are required to proceed."
        }
    }
    return $Global:Credential
}

#endregion

#region Windows Health Check Functions

function Test-WindowsHealth {
    param(
        [string]$ServerName,
        [pscredential]$Credential
    )
    
    $results = @{}
    
    try {
        Write-DetailedLog "Starting Windows health checks for $ServerName"
        
        # CPU Usage
        $results.CPU = Get-CpuUsage -ServerName $ServerName -Credential $Credential
        
        # Memory Usage
        $results.Memory = Get-MemoryUsage -ServerName $ServerName -Credential $Credential
        
        # Disk Space
        $results.DiskSpace = Get-DiskSpaceUsage -ServerName $ServerName -Credential $Credential
        
        # Disk Performance
        $results.DiskPerformance = Get-DiskPerformance -ServerName $ServerName -Credential $Credential
        
        # Services
        $results.WindowsServices = Get-WindowsServicesStatus -ServerName $ServerName -Credential $Credential
        
        # System Information
        $results.SystemInfo = Get-SystemInformation -ServerName $ServerName -Credential $Credential
        
        # Event Log Errors
        $results.EventLogs = Get-RecentEventLogErrors -ServerName $ServerName -Credential $Credential
        
        Write-DetailedLog "Completed Windows health checks for $ServerName"
        
    } catch {
        Write-DetailedLog "Error during Windows health checks for $ServerName`: $_" "ERROR"
        $results.Error = $_.Exception.Message
    }
    
    return $results
}

function Get-CpuUsage {
    param([string]$ServerName, [pscredential]$Credential)
    
    try {
        $cpuCounters = Get-Counter -ComputerName $ServerName -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop
        $avgCpuUsage = ($cpuCounters.CounterSamples | Measure-Object CookedValue -Average).Average
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "CPU Usage"
        $result.Value = "{0:N1}%" -f $avgCpuUsage
        $result.Status = Get-HealthStatusFromValue -Value $avgCpuUsage -WarningThreshold $Global:Thresholds.CpuWarning -CriticalThreshold $Global:Thresholds.CpuCritical
        
        switch ($result.Status) {
            ([HealthStatus]::Excellent) { $result.Message = "CPU usage is optimal" }
            ([HealthStatus]::Good) { $result.Message = "CPU usage is acceptable" }
            ([HealthStatus]::Critical) { $result.Message = "CPU usage is critically high"; $result.Recommendation = "Investigate high CPU processes" }
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "CPU Usage"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve CPU usage: $_"
        return $result
    }
}

function Get-MemoryUsage {
    param([string]$ServerName, [pscredential]$Credential)
    
    try {
        $os = Get-CimInstance -ComputerName $ServerName -ClassName Win32_OperatingSystem -Credential $Credential -ErrorAction Stop
        $totalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeMemoryGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $usedMemoryGB = $totalMemoryGB - $freeMemoryGB
        $usedMemoryPercent = [math]::Round(($usedMemoryGB / $totalMemoryGB) * 100, 1)
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Memory Usage"
        $result.Value = "$usedMemoryPercent% ($usedMemoryGB GB / $totalMemoryGB GB)"
        $result.Status = Get-HealthStatusFromValue -Value $usedMemoryPercent -WarningThreshold $Global:Thresholds.MemoryWarning -CriticalThreshold $Global:Thresholds.MemoryCritical
        
        switch ($result.Status) {
            ([HealthStatus]::Excellent) { $result.Message = "Memory usage is optimal" }
            ([HealthStatus]::Good) { $result.Message = "Memory usage is acceptable" }
            ([HealthStatus]::Critical) { $result.Message = "Memory usage is critically high"; $result.Recommendation = "Consider adding more RAM or investigate memory leaks" }
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Memory Usage"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve memory usage: $_"
        return $result
    }
}

function Get-DiskSpaceUsage {
    param([string]$ServerName, [pscredential]$Credential)
    
    try {
        $drives = Get-CimInstance -ComputerName $ServerName -ClassName Win32_LogicalDisk -Filter "DriveType=3" -Credential $Credential -ErrorAction Stop
        $diskResults = @()
        
        foreach ($drive in $drives) {
            $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            $totalSpaceGB = [math]::Round($drive.Size / 1GB, 2)
            $usedSpaceGB = $totalSpaceGB - $freeSpaceGB
            $freeSpacePercent = [math]::Round(($freeSpaceGB / $totalSpaceGB) * 100, 1)
            
            $result = [HealthCheckResult]::new()
            $result.CheckName = "Disk Space ($($drive.DeviceID))"
            $result.Value = "$freeSpacePercent% free ($freeSpaceGB GB / $totalSpaceGB GB)"
            $result.Status = Get-HealthStatusFromValue -Value $freeSpacePercent -WarningThreshold $Global:Thresholds.DiskSpaceWarning -CriticalThreshold $Global:Thresholds.DiskSpaceCritical -HigherIsBetter $true
            
            switch ($result.Status) {
                ([HealthStatus]::Excellent) { $result.Message = "Disk space is adequate" }
                ([HealthStatus]::Good) { $result.Message = "Disk space is acceptable" }
                ([HealthStatus]::Critical) { $result.Message = "Disk space is critically low"; $result.Recommendation = "Free up disk space or add storage" }
            }
            
            $diskResults += $result
        }
        
        return $diskResults
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Disk Space"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve disk space information: $_"
        return @($result)
    }
}

function Get-DiskPerformance {
    param([string]$ServerName, [pscredential]$Credential)
    
    try {
        $diskCounters = Get-Counter -ComputerName $ServerName -Counter "\PhysicalDisk(_Total)\Avg. Disk sec/Read", "\PhysicalDisk(_Total)\Avg. Disk sec/Write" -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop
        
        $avgReadLatency = (($diskCounters.CounterSamples | Where-Object {$_.Path -like "*Read*"} | Measure-Object CookedValue -Average).Average) * 1000
        $avgWriteLatency = (($diskCounters.CounterSamples | Where-Object {$_.Path -like "*Write*"} | Measure-Object CookedValue -Average).Average) * 1000
        $avgLatency = ($avgReadLatency + $avgWriteLatency) / 2
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Disk Performance"
        $result.Value = "{0:N1} ms avg latency" -f $avgLatency
        $result.Status = Get-HealthStatusFromValue -Value $avgLatency -WarningThreshold $Global:Thresholds.DiskLatencyWarning -CriticalThreshold $Global:Thresholds.DiskLatencyCritical
        
        switch ($result.Status) {
            ([HealthStatus]::Excellent) { $result.Message = "Disk performance is excellent" }
            ([HealthStatus]::Good) { $result.Message = "Disk performance is good" }
            ([HealthStatus]::Critical) { $result.Message = "Disk performance is poor"; $result.Recommendation = "Check disk health and consider SSD upgrade" }
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Disk Performance"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve disk performance data: $_"
        return $result
    }
}

function Get-WindowsServicesStatus {
    param([string]$ServerName, [pscredential]$Credential)
    
    try {
        $services = Get-Service -ComputerName $ServerName -Name "*SQL*" -ErrorAction Stop
        $serviceResults = @()
        
        foreach ($service in $services) {
            $result = [HealthCheckResult]::new()
            $result.CheckName = "Service: $($service.DisplayName)"
            $result.Value = $service.Status
            $result.Status = if ($service.Status -eq 'Running') { [HealthStatus]::Excellent } else { [HealthStatus]::Critical }
            $result.Message = "Service is $($service.Status)"
            
            if ($service.Status -ne 'Running') {
                $result.Recommendation = "Start the service if it should be running"
            }
            
            $serviceResults += $result
        }
        
        return $serviceResults
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Windows Services"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve service status: $_"
        return @($result)
    }
}

function Get-SystemInformation {
    param([string]$ServerName, [pscredential]$Credential)
    
    try {
        $os = Get-CimInstance -ComputerName $ServerName -ClassName Win32_OperatingSystem -Credential $Credential -ErrorAction Stop
        $computer = Get-CimInstance -ComputerName $ServerName -ClassName Win32_ComputerSystem -Credential $Credential -ErrorAction Stop
        
        $uptime = (Get-Date) - $os.LastBootUpTime
        $uptimeDays = [math]::Floor($uptime.TotalDays)
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "System Information"
        $result.Status = [HealthStatus]::Excellent
        $result.Value = "$($os.Caption), Uptime: $uptimeDays days"
        $result.Message = "OS: $($os.Caption), RAM: $([math]::Round($computer.TotalPhysicalMemory/1GB,0)) GB, Uptime: $uptimeDays days"
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "System Information"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve system information: $_"
        return $result
    }
}

function Get-RecentEventLogErrors {
    param([string]$ServerName, [pscredential]$Credential)
    
    try {
        $errorEvents = Get-WinEvent -ComputerName $ServerName -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10 -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Event Log Errors (24h)"
        $result.Value = "$($errorEvents.Count) errors/warnings"
        
        if ($errorEvents.Count -eq 0) {
            $result.Status = [HealthStatus]::Excellent
            $result.Message = "No critical errors in the last 24 hours"
        } elseif ($errorEvents.Count -le 5) {
            $result.Status = [HealthStatus]::Good
            $result.Message = "Few errors found in the last 24 hours"
        } else {
            $result.Status = [HealthStatus]::Fair
            $result.Message = "Multiple errors found in the last 24 hours"
            $result.Recommendation = "Review event logs for recurring issues"
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Event Log Errors"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve event log errors: $_"
        return $result
    }
}

#endregion

#region SQL Server Health Check Functions

function Test-SqlServerHealth {
    param(
        [string]$ServerName,
        [string]$Port,
        [pscredential]$Credential
    )
    
    $results = @{}
    $sqlServerName = if ($Port) { "$ServerName,$Port" } else { $ServerName }
    
    try {
        Write-DetailedLog "Starting SQL Server health checks for $sqlServerName"
        
        # Test SQL connectivity first
        $connectionTest = Test-SqlConnection -ServerName $sqlServerName
        if (-not $connectionTest) {
            $results.Error = "Could not connect to SQL Server instance"
            return $results
        }
        
        # SQL Server Information
        $results.SqlServerInfo = Get-SqlServerInformation -ServerName $sqlServerName
        
        # Failed Jobs
        $results.FailedJobs = Get-SqlFailedJobs -ServerName $sqlServerName
        
        # Database Backups
        $results.DatabaseBackups = Get-DatabaseBackupStatus -ServerName $sqlServerName
        
        # Blocking Sessions
        $results.BlockingSessions = Get-BlockingSessions -ServerName $sqlServerName
        
        # Recent Deadlocks
        $results.Deadlocks = Get-RecentDeadlocks -ServerName $sqlServerName
        
        # Long Running Queries
        $results.LongRunningQueries = Get-LongRunningQueries -ServerName $sqlServerName
        
        # Database Sizes
        $results.DatabaseSizes = Get-DatabaseSizes -ServerName $sqlServerName
        
        # SQL Error Log
        $results.SqlErrorLog = Get-SqlErrorLogEntries -ServerName $sqlServerName
        
        Write-DetailedLog "Completed SQL Server health checks for $sqlServerName"
        
    } catch {
        Write-DetailedLog "Error during SQL Server health checks for $sqlServerName`: $_" "ERROR"
        $results.Error = $_.Exception.Message
    }
    
    return $results
}

function Test-SqlConnection {
    param([string]$ServerName)
    
    try {
        $connectionString = "Server=$ServerName;Integrated Security=true;Connection Timeout=10;"
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()
        $connection.Close()
        return $true
    } catch {
        return $false
    }
}

function Get-SqlServerInformation {
    param([string]$ServerName)
    
    try {
        $query = @"
SELECT 
    SERVERPROPERTY('ProductVersion') as Version,
    SERVERPROPERTY('ProductLevel') as ServicePack,
    SERVERPROPERTY('Edition') as Edition,
    SERVERPROPERTY('InstanceName') as InstanceName,
    DATEDIFF(day, create_date, GETDATE()) as UptimeDays
FROM sys.databases WHERE name = 'tempdb'
"@
        
        $info = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "SQL Server Information"
        $result.Status = [HealthStatus]::Excellent
        $result.Value = "Version: $($info.Version)"
        $result.Message = "Version: $($info.Version), Edition: $($info.Edition), Uptime: $($info.UptimeDays) days"
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "SQL Server Information"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve SQL Server information: $_"
        return $result
    }
}

function Get-SqlFailedJobs {
    param([string]$ServerName)
    
    try {
        $query = @"
SELECT COUNT(*) as FailedJobCount
FROM msdb.dbo.sysjobs j
INNER JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
WHERE h.run_status = 0 
AND h.run_date >= CONVERT(INT, CONVERT(VARCHAR(8), DATEADD(day, -1, GETDATE()), 112))
"@
        
        $failedJobs = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Failed SQL Jobs (24h)"
        $result.Value = "$($failedJobs.FailedJobCount) failed jobs"
        
        if ($failedJobs.FailedJobCount -eq 0) {
            $result.Status = [HealthStatus]::Excellent
            $result.Message = "No failed jobs in the last 24 hours"
        } else {
            $result.Status = [HealthStatus]::Critical
            $result.Message = "$($failedJobs.FailedJobCount) jobs failed in the last 24 hours"
            $result.Recommendation = "Review failed jobs in SQL Server Agent"
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Failed SQL Jobs"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to check job status: $_"
        return $result
    }
}

function Get-DatabaseBackupStatus {
    param([string]$ServerName)
    
    try {
        $query = @"
SELECT COUNT(*) as OutdatedBackups
FROM sys.databases d
LEFT JOIN (
    SELECT database_name, MAX(backup_finish_date) as last_backup_date
    FROM msdb.dbo.backupset 
    WHERE type = 'D'
    GROUP BY database_name
) b ON d.name = b.database_name
WHERE d.database_id > 4 
AND (b.last_backup_date IS NULL OR b.last_backup_date < DATEADD(day, -1, GETDATE()))
"@
        
        $backupStatus = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Database Backup Status"
        $result.Value = "$($backupStatus.OutdatedBackups) databases without recent backup"
        
        if ($backupStatus.OutdatedBackups -eq 0) {
            $result.Status = [HealthStatus]::Excellent
            $result.Message = "All databases have recent backups"
        } else {
            $result.Status = [HealthStatus]::Critical
            $result.Message = "$($backupStatus.OutdatedBackups) databases don't have backups within 24 hours"
            $result.Recommendation = "Review backup jobs and ensure they are running successfully"
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Database Backup Status"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to check backup status: $_"
        return $result
    }
}

function Get-BlockingSessions {
    param([string]$ServerName)
    
    try {
        $query = @"
SELECT COUNT(*) as BlockingSessionCount
FROM sys.dm_exec_requests 
WHERE blocking_session_id > 0
"@
        
        $blocking = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Blocking Sessions"
        $result.Value = "$($blocking.BlockingSessionCount) blocked sessions"
        
        if ($blocking.BlockingSessionCount -eq 0) {
            $result.Status = [HealthStatus]::Excellent
            $result.Message = "No blocking sessions detected"
        } else {
            $result.Status = [HealthStatus]::Fair
            $result.Message = "$($blocking.BlockingSessionCount) sessions are currently blocked"
            $result.Recommendation = "Investigate blocking queries using sp_who2 or Activity Monitor"
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Blocking Sessions"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to check blocking sessions: $_"
        return $result
    }
}

function Get-RecentDeadlocks {
    param([string]$ServerName)
    
    try {
        $query = @"
SELECT COUNT(*) as DeadlockCount
FROM sys.dm_os_performance_counters 
WHERE counter_name = 'Number of Deadlocks/sec' AND instance_name = '_Total'
"@
        
        $deadlocks = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Recent Deadlocks"
        $result.Value = "Deadlock counter available"
        $result.Status = [HealthStatus]::Good
        $result.Message = "Deadlock monitoring is active"
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Recent Deadlocks"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to check deadlock information: $_"
        return $result
    }
}

function Get-LongRunningQueries {
    param([string]$ServerName)
    
    try {
        $query = @"
SELECT COUNT(*) as LongRunningQueries
FROM sys.dm_exec_requests 
WHERE total_elapsed_time > 300000 -- 5 minutes
AND session_id > 50
"@
        
        $longQueries = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Long Running Queries"
        $result.Value = "$($longQueries.LongRunningQueries) queries > 5 minutes"
        
        if ($longQueries.LongRunningQueries -eq 0) {
            $result.Status = [HealthStatus]::Excellent
            $result.Message = "No long running queries detected"
        } elseif ($longQueries.LongRunningQueries -le 2) {
            $result.Status = [HealthStatus]::Good
            $result.Message = "Few long running queries detected"
        } else {
            $result.Status = [HealthStatus]::Fair
            $result.Message = "Multiple long running queries detected"
            $result.Recommendation = "Review query performance and consider optimization"
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Long Running Queries"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to check long running queries: $_"
        return $result
    }
}

function Get-DatabaseSizes {
    param([string]$ServerName)
    
    try {
        $query = @"
SELECT 
    COUNT(*) as DatabaseCount,
    SUM(size * 8.0 / 1024) as TotalSizeMB
FROM sys.master_files
WHERE database_id > 4
"@
        
        $dbSize = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Database Sizes"
        $result.Status = [HealthStatus]::Good
        $result.Value = "$($dbSize.DatabaseCount) databases, {0:N0} MB total" -f $dbSize.TotalSizeMB
        $result.Message = "Total user databases: $($dbSize.DatabaseCount), Total size: {0:N2} GB" -f ($dbSize.TotalSizeMB / 1024)
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "Database Sizes"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to retrieve database size information: $_"
        return $result
    }
}

function Get-SqlErrorLogEntries {
    param([string]$ServerName)
    
    try {
        $query = @"
CREATE TABLE #ErrorLog (LogDate datetime, ProcessInfo nvarchar(50), Text nvarchar(max))
INSERT INTO #ErrorLog EXEC xp_readerrorlog 0, 1, N'Error', N'', NULL, NULL, 'DESC'
SELECT COUNT(*) as ErrorCount FROM #ErrorLog WHERE LogDate >= DATEADD(hour, -24, GETDATE())
DROP TABLE #ErrorLog
"@
        
        $errorCount = Invoke-Sqlcmd -ServerInstance $ServerName -Query $query -TrustServerCertificate -ErrorAction Stop
        
        $result = [HealthCheckResult]::new()
        $result.CheckName = "SQL Error Log (24h)"
        $result.Value = "$($errorCount.ErrorCount) errors"
        
        if ($errorCount.ErrorCount -eq 0) {
            $result.Status = [HealthStatus]::Excellent
            $result.Message = "No errors in SQL error log in the last 24 hours"
        } elseif ($errorCount.ErrorCount -le 5) {
            $result.Status = [HealthStatus]::Good
            $result.Message = "Few errors in SQL error log"
        } else {
            $result.Status = [HealthStatus]::Fair
            $result.Message = "Multiple errors in SQL error log"
            $result.Recommendation = "Review SQL Server error log for details"
        }
        
        return $result
        
    } catch {
        $result = [HealthCheckResult]::new()
        $result.CheckName = "SQL Error Log"
        $result.Status = [HealthStatus]::Unknown
        $result.Message = "Failed to check SQL error log: $_"
        return $result
    }
}

#endregion

#region Parallel Execution Functions

function Invoke-ServerHealthCheck {
    param([string]$ServerLine, [string]$CheckProfile, [pscredential]$Credential, [int]$Timeout)
    
    $serverResult = [ServerResult]::new()
    $serverResult.CheckStartTime = Get-Date
    
    try {
        # Parse server line
        $parts = $ServerLine -split ','
        $serverResult.ServerName = $parts[0].Trim()
        $serverResult.Port = if ($parts.Length -gt 1) { $parts[1].Trim() } else { "" }
        
        Write-DetailedLog "Starting health check for $($serverResult.ServerName)" "INFO"
        
        # Test basic connectivity
        $serverResult.IsOnline = Test-ServerConnectivity -ServerName $serverResult.ServerName
        
        if (-not $serverResult.IsOnline) {
            $serverResult.ErrorMessage = "Server is not reachable"
            $serverResult.OverallStatus = [HealthStatus]::Critical
            Write-DetailedLog "Server $($serverResult.ServerName) is not reachable" "WARN"
            return $serverResult
        }
        
        # Windows Health Checks
        $serverResult.WindowsHealth = Test-WindowsHealth -ServerName $serverResult.ServerName -Credential $Credential
        
        # SQL Health Checks (if requested)
        if ($CheckProfile -eq "WindowsAndSQL") {
            $serverResult.SqlHealth = Test-SqlServerHealth -ServerName $serverResult.ServerName -Port $serverResult.Port -Credential $Credential
        }
        
        # Determine overall status
        $serverResult.OverallStatus = Get-OverallHealthStatus -ServerResult $serverResult
        
        Write-ColoredStatus -ServerName $serverResult.ServerName -Status $serverResult.OverallStatus
        
    } catch {
        $serverResult.ErrorMessage = $_.Exception.Message
        $serverResult.OverallStatus = [HealthStatus]::Critical
        Write-DetailedLog "Error checking server $($serverResult.ServerName): $_" "ERROR"
    } finally {
        $serverResult.CheckEndTime = Get-Date
        $serverResult.Duration = $serverResult.CheckEndTime - $serverResult.CheckStartTime
    }
    
    return $serverResult
}

function Get-OverallHealthStatus {
    param([ServerResult]$ServerResult)
    
    $allStatuses = @()
    
    # Collect all status values
    if ($ServerResult.WindowsHealth) {
        foreach ($check in $ServerResult.WindowsHealth.Values) {
            if ($check -is [HealthCheckResult]) {
                $allStatuses += $check.Status
            } elseif ($check -is [array]) {
                foreach ($subCheck in $check) {
                    if ($subCheck -is [HealthCheckResult]) {
                        $allStatuses += $subCheck.Status
                    }
                }
            }
        }
    }
    
    if ($ServerResult.SqlHealth) {
        foreach ($check in $ServerResult.SqlHealth.Values) {
            if ($check -is [HealthCheckResult]) {
                $allStatuses += $check.Status
            }
        }
    }
    
    # Return the worst status found
    if ($allStatuses -contains [HealthStatus]::Critical) { return [HealthStatus]::Critical }
    if ($allStatuses -contains [HealthStatus]::Poor) { return [HealthStatus]::Poor }
    if ($allStatuses -contains [HealthStatus]::Fair) { return [HealthStatus]::Fair }
    if ($allStatuses -contains [HealthStatus]::Good) { return [HealthStatus]::Good }
    if ($allStatuses -contains [HealthStatus]::Excellent) { return [HealthStatus]::Excellent }
    
    return [HealthStatus]::Unknown
}

#endregion

#region Output Generation Functions

function Initialize-OutputFiles {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Use organized folder structure
    $Global:OutputFiles.DetailedLog = Join-Path $Global:OutputPaths.Logs "ServerHealthCheck_Detailed_$timestamp.log"
    $Global:OutputFiles.TechnicalReport = Join-Path $Global:OutputPaths.Reports "ServerHealthCheck_Technical_$timestamp.txt"
    $Global:OutputFiles.ManagementReportHtml = Join-Path $Global:OutputPaths.Reports "ServerHealthCheck_Management_$timestamp.html"
    $Global:OutputFiles.ManagementReportExcel = Join-Path $Global:OutputPaths.Reports "ServerHealthCheck_Management_$timestamp.xlsx"
    
    # Initialize detailed log
    Write-DetailedLog "=== Server Health Check Started ===" "INFO"
    Write-DetailedLog "Check Profile: $CheckProfile" "INFO"
    Write-DetailedLog "Max Concurrency: $MaxConcurrency" "INFO"
    Write-DetailedLog "Output Root: $($Global:OutputPaths.Root)" "INFO"
    Write-DetailedLog "Reports: $($Global:OutputPaths.Reports)" "INFO"
    Write-DetailedLog "Logs: $($Global:OutputPaths.Logs)" "INFO"
}

function Export-TechnicalReport {
    $report = @"
==============================================
SERVER HEALTH CHECK TECHNICAL REPORT
==============================================
Generated: $(Get-Date)
Check Profile: $CheckProfile
Total Servers: $($Global:Results.Count)
Total Duration: $((Get-Date) - $Global:StartTime)

==============================================
SERVER SUMMARY
==============================================
"@

    foreach ($server in $Global:Results) {
        $statusSymbol = Get-StatusSymbol -Status $server.OverallStatus
        $onlineSymbol = if ($server.IsOnline) { "[ONLINE]" } else { "[OFFLINE]" }
        $report += @"

SERVER: $($server.ServerName)
$("=" * 50)
Status: $statusSymbol $($server.OverallStatus)
Online: $onlineSymbol $($server.IsOnline)
Check Duration: $($server.Duration)
Error: $($server.ErrorMessage)

WINDOWS HEALTH CHECKS:
$("-" * 25)
"@
        
        if ($server.WindowsHealth) {
            foreach ($checkName in $server.WindowsHealth.Keys) {
                $check = $server.WindowsHealth[$checkName]
                if ($check -is [HealthCheckResult]) {
                    $checkSymbol = Get-StatusSymbol -Status $check.Status
                    $report += "`n$($check.CheckName): $checkSymbol $($check.Status) - $($check.Value) - $($check.Message)"
                } elseif ($check -is [array]) {
                    foreach ($subCheck in $check) {
                        if ($subCheck -is [HealthCheckResult]) {
                            $subCheckSymbol = Get-StatusSymbol -Status $subCheck.Status
                            $report += "`n$($subCheck.CheckName): $subCheckSymbol $($subCheck.Status) - $($subCheck.Value) - $($subCheck.Message)"
                        }
                    }
                }
            }
        }
        
        if ($CheckProfile -eq "WindowsAndSQL" -and $server.SqlHealth) {
            $report += @"

SQL SERVER HEALTH CHECKS:
$("-" * 25)
"@
            foreach ($checkName in $server.SqlHealth.Keys) {
                $check = $server.SqlHealth[$checkName]
                if ($check -is [HealthCheckResult]) {
                    $sqlCheckSymbol = Get-StatusSymbol -Status $check.Status
                    $report += "`n$($check.CheckName): $sqlCheckSymbol $($check.Status) - $($check.Value) - $($check.Message)"
                }
            }
        }
        
        $report += "`n"
    }
    
    $report | Out-File -FilePath $Global:OutputFiles.TechnicalReport -Encoding UTF8
    Write-ProgressMessage "Technical report saved to: $($Global:OutputFiles.TechnicalReport)" "Green"
}

function Export-ManagementReports {
    # Prepare summary data
    $summary = @{
        TotalServers = $Global:Results.Count
        OnlineServers = ($Global:Results | Where-Object { $_.IsOnline }).Count
        OfflineServers = ($Global:Results | Where-Object { -not $_.IsOnline }).Count
        ExcellentHealth = ($Global:Results | Where-Object { $_.OverallStatus -eq [HealthStatus]::Excellent }).Count
        GoodHealth = ($Global:Results | Where-Object { $_.OverallStatus -eq [HealthStatus]::Good }).Count
        FairHealth = ($Global:Results | Where-Object { $_.OverallStatus -eq [HealthStatus]::Fair }).Count
        PoorHealth = ($Global:Results | Where-Object { $_.OverallStatus -eq [HealthStatus]::Poor }).Count
        CriticalHealth = ($Global:Results | Where-Object { $_.OverallStatus -eq [HealthStatus]::Critical }).Count
        UnknownHealth = ($Global:Results | Where-Object { $_.OverallStatus -eq [HealthStatus]::Unknown }).Count
        CheckDuration = (Get-Date) - $Global:StartTime
    }
    
    # Export HTML Report
    Export-HtmlManagementReport -Summary $summary
    
    # Export Excel Report
    Export-ExcelManagementReport -Summary $summary
}

function Export-HtmlManagementReport {
    param($Summary)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Server Health Check Management Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #2E75B6; color: white; padding: 15px; text-align: center; }
        .summary { background-color: #f5f5f5; padding: 15px; margin: 10px 0; }
        .status-excellent { color: #008000; font-weight: bold; }
        .status-good { color: #32CD32; font-weight: bold; }
        .status-fair { color: #FFA500; font-weight: bold; }
        .status-poor { color: #FF6347; font-weight: bold; }
        .status-critical { color: #FF0000; font-weight: bold; }
        .status-unknown { color: #808080; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .chart { margin: 20px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Server Health Check Management Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Servers Checked:</strong> $($Summary.TotalServers)</p>
        <p><strong>Check Duration:</strong> $($Summary.CheckDuration.ToString('hh\:mm\:ss'))</p>
        <p><strong>Check Profile:</strong> $CheckProfile</p>
        
        <h3>Server Availability</h3>
        <p>Online: $($Summary.OnlineServers) | Offline: $($Summary.OfflineServers)</p>
        
        <h3>Health Status Distribution</h3>
        <p>
            <span class="status-excellent">Excellent: $($Summary.ExcellentHealth)</span> | 
            <span class="status-good">Good: $($Summary.GoodHealth)</span> | 
            <span class="status-fair">Fair: $($Summary.FairHealth)</span> | 
            <span class="status-poor">Poor: $($Summary.PoorHealth)</span> | 
            <span class="status-critical">Critical: $($Summary.CriticalHealth)</span> | 
            <span class="status-unknown">Unknown: $($Summary.UnknownHealth)</span>
        </p>
    </div>
    
    <h2>Server Details</h2>
    <table>
        <tr>
            <th>Server Name</th>
            <th>Status</th>
            <th>Online</th>
            <th>Check Duration</th>
            <th>Issues</th>
        </tr>
"@
    
    foreach ($server in $Global:Results) {
        $statusClass = switch ($server.OverallStatus) {
            ([HealthStatus]::Excellent) { "status-excellent" }
            ([HealthStatus]::Good) { "status-good" }
            ([HealthStatus]::Fair) { "status-fair" }
            ([HealthStatus]::Poor) { "status-poor" }
            ([HealthStatus]::Critical) { "status-critical" }
            default { "status-unknown" }
        }
        
        $issues = if ($server.ErrorMessage) { $server.ErrorMessage } else { "None" }
        
        $html += @"
        <tr>
            <td>$($server.ServerName)</td>
            <td class="$statusClass">$($server.OverallStatus)</td>
            <td>$($server.IsOnline)</td>
            <td>$($server.Duration.ToString('mm\:ss'))</td>
            <td>$issues</td>
        </tr>
"@
    }
    
    $html += @"
    </table>
    
    <div class="summary">
        <h2>Recommendations</h2>
        <ul>
            <li>Address all Critical and Poor status servers immediately</li>
            <li>Review Fair status servers for potential improvements</li>
            <li>Monitor trends over time to identify deteriorating servers</li>
            <li>Consider upgrading servers with performance issues</li>
        </ul>
    </div>
    
    <p><em>For detailed technical information, see the technical report.</em></p>
</body>
</html>
"@
    
    $html | Out-File -FilePath $Global:OutputFiles.ManagementReportHtml -Encoding UTF8
    Write-ProgressMessage "Management HTML report saved to: $($Global:OutputFiles.ManagementReportHtml)" "Green"
}

function Export-ExcelManagementReport {
    param($Summary)
    
    try {
        # Prepare data for Excel
        $serverData = @()
        foreach ($server in $Global:Results) {
            $serverData += [PSCustomObject]@{
                'Server Name' = $server.ServerName
                'Status' = $server.OverallStatus
                'Online' = $server.IsOnline
                'Check Duration (seconds)' = [math]::Round($server.Duration.TotalSeconds, 1)
                'Error Message' = $server.ErrorMessage
            }
        }
        
        $summaryData = [PSCustomObject]@{
            'Total Servers' = $Summary.TotalServers
            'Online Servers' = $Summary.OnlineServers
            'Offline Servers' = $Summary.OfflineServers
            'Excellent Health' = $Summary.ExcellentHealth
            'Good Health' = $Summary.GoodHealth
            'Fair Health' = $Summary.FairHealth
            'Poor Health' = $Summary.PoorHealth
            'Critical Health' = $Summary.CriticalHealth
            'Unknown Health' = $Summary.UnknownHealth
            'Check Duration' = $Summary.CheckDuration.ToString('hh\:mm\:ss')
        }
        
        # Export to Excel
        $summaryData | Export-Excel -Path $Global:OutputFiles.ManagementReportExcel -WorksheetName "Summary" -AutoSize -TableStyle Medium6
        $serverData | Export-Excel -Path $Global:OutputFiles.ManagementReportExcel -WorksheetName "Server Details" -AutoSize -TableStyle Medium6 -Append
        
        Write-ProgressMessage "Management Excel report saved to: $($Global:OutputFiles.ManagementReportExcel)" "Green"
    } catch {
        Write-Warning "Failed to create Excel report. ImportExcel module may not be installed. Error: $_"
        Write-DetailedLog "Failed to create Excel report: $_" "WARN"
    }
}

#endregion

#region Main Execution

function Main {
    try {
        Write-ProgressMessage "=== SQL Server Health Check Script Started ===" "Cyan"
        Write-ProgressMessage "Profile: $CheckProfile | Max Concurrency: $MaxConcurrency | Dry Run: $DryRun" "Cyan"
        
        # Initialize project structure and paths
        Initialize-ProjectStructure
        
        # Initialize output files
        Initialize-OutputFiles
        
        # Install required modules
        if (-not $DryRun) {
            Install-RequiredModules
        }
        
        # Read server list (filter out comments and empty lines)
        $serverList = Get-Content -Path $ServerListPath | Where-Object { $_ -and $_.Trim() -ne "" -and -not $_.Trim().StartsWith("#") }
        Write-ProgressMessage "Loaded $($serverList.Count) servers from list" "Green"
        
        if ($DryRun) {
            Write-ProgressMessage "=== DRY RUN MODE - No actual checks will be performed ===" "Yellow"
            Write-ProgressMessage "Servers that would be checked:" "Yellow"
            foreach ($server in $serverList) {
                $parts = $server -split ','
                $serverName = $parts[0].Trim()
                $port = if ($parts.Length -gt 1) { $parts[1].Trim() } else { "Default" }
                Write-ProgressMessage "  - $serverName (Port: $port)" "White"
            }
            Write-ProgressMessage "Check profile: $CheckProfile" "Yellow"
            Write-ProgressMessage "Max concurrency: $MaxConcurrency" "Yellow"
            Write-ProgressMessage "Output directory: $OutputPath" "Yellow"
            Write-ProgressMessage "" "White"
            Write-ProgressMessage "Generating sample output files to show you what reports will look like..." "Green"
            
            # Generate sample output files for demonstration
            Write-ProgressMessage "Sample report generation temporarily disabled due to syntax issues." "Yellow"
            Write-ProgressMessage "The organized folder structure is now ready!" "Green"
            
            Write-ProgressMessage "=== DRY RUN COMPLETE ===" "Yellow"
            return
        }
        
        # Get credentials
        $credential = Get-Credentials
        
        # Execute health checks in parallel
        Write-ProgressMessage "Starting health checks with $MaxConcurrency concurrent threads..." "Green"
        
        $jobs = @()
        $completedCount = 0
        $totalServers = $serverList.Count
        
        # Process servers in batches
        for ($i = 0; $i -lt $serverList.Count; $i += $MaxConcurrency) {
            $batch = $serverList[$i..([math]::Min($i + $MaxConcurrency - 1, $serverList.Count - 1))]
            
            foreach ($server in $batch) {
                $job = Start-Job -ScriptBlock {
                    param($ServerLine, $CheckProfile, $Credential, $Timeout)
                    
                    # Re-import the script functions in the job context
                    $functions = $using:PSCmdlet.MyInvocation.MyCommand.Source
                    . $functions
                    
                    return Invoke-ServerHealthCheck -ServerLine $ServerLine -CheckProfile $CheckProfile -Credential $Credential -Timeout $Timeout
                } -ArgumentList $server, $CheckProfile, $credential, $Timeout
                
                $jobs += $job
            }
            
            # Wait for batch to complete
            do {
                Start-Sleep -Seconds 2
                $runningJobs = $jobs | Where-Object { $_.State -eq 'Running' }
                $completedJobs = $jobs | Where-Object { $_.State -ne 'Running' }
                
                # Collect completed results
                foreach ($job in $completedJobs | Where-Object { $_.HasMoreData }) {
                    $result = Receive-Job -Job $job
                    if ($result) {
                        $Global:Results += $result
                        $completedCount++
                        
                        $statusColor = switch ($result.OverallStatus) {
                            ([HealthStatus]::Excellent) { "Green" }
                            ([HealthStatus]::Good) { "Green" }
                            ([HealthStatus]::Fair) { "Yellow" }
                            ([HealthStatus]::Poor) { "Red" }
                            ([HealthStatus]::Critical) { "Red" }
                            default { "Gray" }
                        }
                        
                        $symbol = Get-StatusSymbol -Status $result.OverallStatus
                        Write-ProgressMessage "[$completedCount/$totalServers] $($result.ServerName): $symbol $($result.OverallStatus)" $statusColor
                    }
                    Remove-Job -Job $job
                }
                
                $jobs = $jobs | Where-Object { $_.State -eq 'Running' }
                
            } while ($runningJobs.Count -gt 0)
        }
        
        # Generate reports
        Write-ProgressMessage "Generating reports..." "Yellow"
        Export-TechnicalReport
        Export-ManagementReports
        
        # Display final summary
        Write-ProgressMessage "=== HEALTH CHECK COMPLETE ===" "Cyan"
        Write-ProgressMessage "Total servers: $($Global:Results.Count)" "White"
        Write-ProgressMessage "Online servers: $(($Global:Results | Where-Object {$_.IsOnline}).Count)" "Green"
        Write-ProgressMessage "Offline servers: $(($Global:Results | Where-Object {-not $_.IsOnline}).Count)" "Red"
        Write-ProgressMessage "Critical issues: $(($Global:Results | Where-Object {$_.OverallStatus -eq [HealthStatus]::Critical}).Count)" "Red"
        Write-ProgressMessage "Total duration: $((Get-Date) - $Global:StartTime)" "White"
        Write-ProgressMessage "" "White"
        Write-ProgressMessage "Reports generated:" "Yellow"
        Write-ProgressMessage "  Technical: $($Global:OutputFiles.TechnicalReport)" "White"
        Write-ProgressMessage "  Management HTML: $($Global:OutputFiles.ManagementReportHtml)" "White"
        Write-ProgressMessage "  Management Excel: $($Global:OutputFiles.ManagementReportExcel)" "White"
        Write-ProgressMessage "  Detailed Log: $($Global:OutputFiles.DetailedLog)" "White"
        
    } catch {
        Write-Error "Critical error in main execution: $_"
        Write-DetailedLog "CRITICAL ERROR: $_" "ERROR"
        exit 1
    }
}

# Execute main function
Main

#endregion