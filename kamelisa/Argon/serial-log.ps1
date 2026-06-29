<#
.SYNOPSIS
    Timestamped serial logger for the Particle Argon boards.

.DESCRIPTION
    Reads a board's USB serial output and writes every line to both the
    console and a log file, prefixing each line with the PC's real
    wall-clock date and time (yyyy-MM-dd HH:mm:ss.fff).

    Auto-reconnects if the board resets or is unplugged, so a single run
    can capture multiple boot/test cycles.

.EXAMPLE
    .\serial-log.ps1 -Port COM5 -Label bob
    .\serial-log.ps1 -Port COM8 -Label alice

.NOTES
    Close any running "particle serial monitor" first — a COM port can
    only be opened by one program at a time. Press Ctrl+C to stop.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Port,
    [string]$Label = "device",
    [int]$BaudRate = 115200,
    [string]$LogDir = (Join-Path $PSScriptRoot "logs")
)

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$startStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogDir ("{0}_{1}.log" -f $Label, $startStamp)

function Write-Log([string]$text) {
    Write-Host $text
    Add-Content -Path $logFile -Value $text -Encoding utf8
}

Write-Host "Logging $Port ($Label) @ $BaudRate baud" -ForegroundColor Cyan
Write-Host "Writing to: $logFile" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
Write-Host ""

$header = "==== serial log start {0}  port={1}  label={2}  baud={3} ====" -f `
    (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Port, $Label, $BaudRate
Add-Content -Path $logFile -Value $header -Encoding utf8

$sp = $null
try {
    while ($true) {
        # (Re)open the port if needed
        if ($null -eq $sp -or -not $sp.IsOpen) {
            try {
                $sp = New-Object System.IO.Ports.SerialPort $Port, $BaudRate, 'None', 8, 'One'
                $sp.ReadTimeout = 500
                $sp.NewLine = "`n"
                $sp.DtrEnable = $true
                $sp.Open()
                Write-Log ("[{0}] --- port {1} opened ---" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $Port)
            }
            catch {
                Start-Sleep -Milliseconds 1000
                continue
            }
        }

        # Read one line
        try {
            $line = $sp.ReadLine()
        }
        catch [System.TimeoutException] {
            continue
        }
        catch {
            Write-Log ("[{0}] --- port lost, reconnecting ---" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"))
            try { $sp.Close() } catch {}
            $sp = $null
            Start-Sleep -Milliseconds 500
            continue
        }

        $line = $line.TrimEnd("`r")
        if ($line.Length -eq 0) { continue }
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        Write-Log ("[$ts] $line")
    }
}
finally {
    if ($sp -and $sp.IsOpen) { $sp.Close() }
    Write-Host ""
    Write-Host "Log saved to $logFile" -ForegroundColor Cyan
}
