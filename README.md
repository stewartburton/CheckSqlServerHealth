# SQL Server Health Check Tool

A comprehensive PowerShell solution for monitoring SQL Server and Windows infrastructure health across enterprise environments. Features organized output, parallel processing, and management-ready reports.

## 🏗️ Project Structure

```
CheckSqlServerHealth/
├── scripts/                      # Core PowerShell scripts
│   ├── CheckSqlServerHealth.ps1  # Main health check script
│   └── Run-HealthCheck.ps1       # Convenience wrapper with presets
├── config/                       # Configuration files
│   └── default-thresholds.json   # Customizable alert thresholds
├── examples/                     # Sample server lists
│   ├── sample-servers.txt        # Test/demo server list
│   ├── production-servers.txt    # Production environment template
│   └── development-servers.txt   # Dev/test environment template
├── outputs/                      # Generated reports (auto-created)
│   ├── reports/                  # HTML and Excel management reports
│   ├── logs/                     # Detailed execution logs
│   └── samples/                  # Sample outputs from dry runs
├── docs/                         # Additional documentation
└── README.md                     # This file
```

## 🚀 Quick Start

### Option 1: Using the Convenience Wrapper (Recommended)
```powershell
# Navigate to the project directory
cd CheckSqlServerHealth

# Run a dry run to see what would be checked
.\scripts\Run-HealthCheck.ps1 -Preset DryRun

# Run health checks on sample servers
.\scripts\Run-HealthCheck.ps1 -Preset QuickCheck

# Run full production health checks
.\scripts\Run-HealthCheck.ps1 -Preset Production
```

### Option 2: Using the Main Script Directly
```powershell
# Basic usage
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "examples\sample-servers.txt"

# Windows-only checks
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "examples\sample-servers.txt" -CheckProfile WindowsOnly

# Dry run to preview
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "examples\sample-servers.txt" -DryRun
```

## 📋 Features

### 🎯 Two Check Profiles
- **`WindowsOnly`**: Windows server health checks only
- **`WindowsAndSQL`**: Both Windows and SQL Server health checks (default)

### 🔄 Execution Modes
- **Standard Mode**: Performs actual health checks
- **Dry Run Mode**: Validates configuration and generates sample reports

### 📊 Multiple Output Formats
- **Management Reports**: HTML and Excel formats for executives
- **Technical Reports**: Detailed text reports for IT operations
- **Execution Logs**: Timestamped detailed logs for troubleshooting

### ⚡ Performance Features
- **Parallel Processing**: Configurable concurrent server checks (1-50)
- **Organized Output**: Clean folder structure prevents clutter
- **Configurable Thresholds**: JSON-based threshold management

## 📝 Server List Format

Create text files with one server per line. Supports multiple formats:

```bash
# examples/my-servers.txt

# Standard server (default SQL port)
SERVER01

# Custom port
SERVER02,1433

# Named instance
CLUSTER01\INSTANCE1

# Comments start with #
# SERVER03  # This server is commented out
```

## 📊 Sample Output

### Console Output During Execution
```
[13:45:23] === SQL Server Health Check Script Started ===
[13:45:23] Profile: WindowsAndSQL | Max Concurrency: 10 | Dry Run: False
[13:45:24] Loaded custom thresholds from config file
[13:45:24] Loaded 12 servers from list
[13:45:26] [1/12] SQL-SERVER01: [EXCELLENT] Excellent
[13:45:27] [2/12] SQL-SERVER02: [GOOD] Good  
[13:45:28] [3/12] DB-PROD-01: [CRITICAL] Critical
[13:45:29] === HEALTH CHECK COMPLETE ===
[13:45:29] Total servers: 12
[13:45:29] Online servers: 11
[13:45:29] Critical issues: 1
[13:45:29] Reports generated:
[13:45:29]   Management HTML: outputs\reports\ServerHealthCheck_Management_20250831_134529.html
[13:45:29]   Technical Report: outputs\reports\ServerHealthCheck_Technical_20250831_134529.txt
```

### Generated Reports

**Management Report (HTML)**
![Management Report Preview](docs/management-report-preview.png)
- Executive dashboard with key metrics
- Color-coded status indicators  
- Critical alerts at the top
- Action recommendations

**Technical Report (Text)**
```
==============================================
SERVER HEALTH CHECK TECHNICAL REPORT
==============================================
Generated: 8/31/2025 1:45:29 PM
Check Profile: WindowsAndSQL
Total Servers: 12
Total Duration: 00:02:45

SERVER: SQL-SERVER01
==================================================
Status: [EXCELLENT] Excellent
Online: [ONLINE] True
Check Duration: 00:00:06

WINDOWS HEALTH CHECKS:
-------------------------
CPU Usage: [GOOD] Good - 45.2% - CPU usage is acceptable
Memory Usage: [EXCELLENT] Excellent - 62.3% (15.8 GB / 32.0 GB) - Memory usage is optimal
Disk Space (C:): [GOOD] Good - 22.1% free (44.2 GB / 200.0 GB) - Disk space is acceptable

SQL SERVER HEALTH CHECKS:
-------------------------
SQL Server Information: [EXCELLENT] Excellent - Version: 15.0.4249.2
Failed SQL Jobs (24h): [EXCELLENT] Excellent - 0 failed jobs
Database Backup Status: [EXCELLENT] Excellent - All databases have recent backups
```

## 🛠️ Configuration

### Custom Thresholds
Modify `config/default-thresholds.json` to customize alert levels:

```json
{
  "thresholds": {
    "diskSpace": {
      "warningPercent": 15,
      "criticalPercent": 5
    },
    "cpu": {
      "warningPercent": 75,
      "criticalPercent": 90
    },
    "memory": {
      "warningPercent": 85,
      "criticalPercent": 95
    },
    "diskLatency": {
      "warningMs": 20,
      "criticalMs": 50
    }
  }
}
```

## 🔍 Health Checks Performed

### Windows Health Checks
| Check | Description | Thresholds |
|-------|-------------|------------|
| **CPU Usage** | Average processor utilization | Warning: 75%, Critical: 90% |
| **Memory Usage** | Physical memory consumption | Warning: 85%, Critical: 95% |
| **Disk Space** | Free space on all drives | Warning: 15%, Critical: 5% |
| **Disk Performance** | I/O latency metrics | Warning: 20ms, Critical: 50ms |
| **Windows Services** | SQL-related service status | Running = Good, Stopped = Critical |
| **System Information** | OS version, uptime, hardware | Informational |
| **Event Log Errors** | Recent system errors (24h) | 0 = Excellent, >5 = Fair |

### SQL Server Health Checks
| Check | Description | Scope |
|-------|-------------|-------|
| **SQL Server Info** | Version, edition, uptime | Instance level |
| **Failed Jobs** | SQL Agent job failures (24h) | Instance level |
| **Database Backups** | Recent backup verification | Database level |
| **Blocking Sessions** | Current blocking queries | Instance level |
| **Long Running Queries** | Queries running >5 minutes | Instance level |
| **Database Sizes** | User database space usage | Database level |
| **SQL Error Log** | Recent SQL errors (24h) | Instance level |

## 🎛️ Advanced Usage

### Custom Parameters
```powershell
# High concurrency for large environments
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "examples\production-servers.txt" -MaxConcurrency 20

# Custom output location  
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "examples\sample-servers.txt" -OutputPath "C:\HealthReports"

# Extended timeout for slow servers
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "examples\sample-servers.txt" -Timeout 600
```

### Scheduled Execution
```powershell
# Create a scheduled task
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File 'C:\Scripts\CheckSqlServerHealth\scripts\Run-HealthCheck.ps1' -Preset Production"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6AM
Register-ScheduledTask -TaskName "Weekly SQL Health Check" -Action $action -Trigger $trigger
```

## 📦 Prerequisites

- **PowerShell 5.1** or later
- **Windows credentials** with access to target servers
- **Network connectivity** to all target servers
- **WMI access** for Windows health checks
- **SQL Server access** for SQL health checks (Windows Authentication)

### Auto-Installed Modules
The script automatically installs these PowerShell modules if missing:
- `SqlServer` - For SQL Server connectivity
- `ImportExcel` - For Excel report generation

## 🔒 Security

- **No credential storage** - credentials are prompted and used in-memory only
- **Windows Authentication** used for both OS and SQL access
- **Secure connections** with trusted server certificates
- **Minimal permissions** required (read-only access)

## 🎯 Presets Reference

| Preset | Description | Profile | Concurrency | Server List |
|--------|-------------|---------|-------------|-------------|
| `Production` | Full production health checks | WindowsAndSQL | 15 | examples/production-servers.txt |
| `Development` | Dev/test environment checks | WindowsAndSQL | 8 | examples/development-servers.txt |
| `QuickCheck` | Basic Windows-only checks | WindowsOnly | 10 | examples/sample-servers.txt |
| `DryRun` | Preview mode with samples | WindowsAndSQL | 10 | examples/sample-servers.txt |

## 📈 Output Files Reference

### During Execution
All output files are automatically organized into folders:

```
outputs/
├── reports/                                    # Management-ready reports
│   ├── ServerHealthCheck_Management_TIMESTAMP.html   # Executive HTML report
│   ├── ServerHealthCheck_Management_TIMESTAMP.xlsx   # Excel analysis
│   └── ServerHealthCheck_Technical_TIMESTAMP.txt     # Detailed technical report
├── logs/                                       # Execution logs  
│   └── ServerHealthCheck_Detailed_TIMESTAMP.log      # Timestamped execution log
└── samples/                                    # Sample outputs (dry run only)
    ├── SAMPLE_ServerHealthCheck_Management_TIMESTAMP.html
    ├── SAMPLE_ServerHealthCheck_Technical_TIMESTAMP.txt  
    └── SAMPLE_ServerHealthCheck_Detailed_TIMESTAMP.log
```

### File Naming Convention
- **Timestamp Format**: `YYYYMMDD_HHMMSS`
- **Sample Files**: Prefixed with `SAMPLE_`
- **Management Reports**: Include both HTML and Excel versions
- **All files**: Include timestamp to prevent overwrites

## 🐛 Troubleshooting

### Common Issues

**Module Installation Fails**
```powershell
# Run PowerShell as Administrator and install manually
Install-Module -Name SqlServer -Scope CurrentUser -Force
Install-Module -Name ImportExcel -Scope CurrentUser -Force
```

**Access Denied Errors**
- Ensure credentials have WMI access to target servers
- Verify SQL Server login permissions
- Check Windows Firewall settings

**Slow Performance**
```powershell
# Reduce concurrency
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "servers.txt" -MaxConcurrency 5

# Increase timeout
.\scripts\CheckSqlServerHealth.ps1 -ServerListPath "servers.txt" -Timeout 600
```

**Script Execution Policy**
```powershell
# Allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Or bypass for single execution
PowerShell.exe -ExecutionPolicy Bypass -File ".\scripts\CheckSqlServerHealth.ps1" -ServerListPath "examples\sample-servers.txt"
```

## 📄 License

This project is provided as-is for educational and enterprise use. Modify and distribute according to your organization's policies.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Test thoroughly with dry runs
4. Submit a pull request with clear description

---

**💡 Pro Tip**: Always run with `-DryRun` first to validate your server list and see sample outputs before executing real health checks on production servers.

**🔗 Quick Links**: 
- [Sample Servers](examples/sample-servers.txt)
- [Configuration](config/default-thresholds.json) 
- [Main Script](scripts/CheckSqlServerHealth.ps1)
- [Wrapper Script](scripts/Run-HealthCheck.ps1)