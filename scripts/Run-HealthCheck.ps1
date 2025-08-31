<#
.SYNOPSIS
Convenience wrapper script to run health checks with common configurations.

.DESCRIPTION
This script provides easy-to-use presets for common health check scenarios.

.PARAMETER Preset
Predefined configuration preset:
- Production: Full health checks on production servers
- Development: Health checks on dev/test servers  
- QuickCheck: Basic Windows-only checks
- DryRun: Preview what would be checked

.PARAMETER ServerListPath
Optional: Override the default server list for the preset

.EXAMPLE
.\Run-HealthCheck.ps1 -Preset Production

.EXAMPLE  
.\Run-HealthCheck.ps1 -Preset DryRun -ServerListPath "..\examples\production-servers.txt"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Production", "Development", "QuickCheck", "DryRun")]
    [string]$Preset,
    
    [Parameter()]
    [string]$ServerListPath
)

$scriptPath = Join-Path $PSScriptRoot "CheckSqlServerHealth.ps1"
$projectRoot = Split-Path -Parent $PSScriptRoot

# Define presets
$presets = @{
    Production = @{
        ServerList = Join-Path $projectRoot "examples\production-servers.txt"
        Profile = "WindowsAndSQL"
        MaxConcurrency = 15
        DryRun = $false
    }
    Development = @{
        ServerList = Join-Path $projectRoot "examples\development-servers.txt"
        Profile = "WindowsAndSQL"
        MaxConcurrency = 8
        DryRun = $false
    }
    QuickCheck = @{
        ServerList = Join-Path $projectRoot "examples\sample-servers.txt"
        Profile = "WindowsOnly"
        MaxConcurrency = 10
        DryRun = $false
    }
    DryRun = @{
        ServerList = Join-Path $projectRoot "examples\sample-servers.txt"
        Profile = "WindowsAndSQL"
        MaxConcurrency = 10
        DryRun = $true
    }
}

# Get preset configuration
$config = $presets[$Preset]

# Override server list if specified
if ($ServerListPath) {
    $config.ServerList = $ServerListPath
}

# Verify server list exists
if (-not (Test-Path $config.ServerList)) {
    Write-Error "Server list not found: $($config.ServerList)"
    Write-Host "Available example files:"
    Get-ChildItem (Join-Path $projectRoot "examples\*.txt") | ForEach-Object {
        Write-Host "  $($_.Name)"
    }
    exit 1
}

Write-Host "Running $Preset preset..." -ForegroundColor Cyan
Write-Host "Server List: $($config.ServerList)" -ForegroundColor White
Write-Host "Profile: $($config.Profile)" -ForegroundColor White
Write-Host "Max Concurrency: $($config.MaxConcurrency)" -ForegroundColor White
Write-Host "Dry Run: $($config.DryRun)" -ForegroundColor White
Write-Host ""

# Build and execute command
$params = @{
    ServerListPath = $config.ServerList
    CheckProfile = $config.Profile
    MaxConcurrency = $config.MaxConcurrency
}

if ($config.DryRun) {
    $params.Add("DryRun", $true)
}

& $scriptPath @params