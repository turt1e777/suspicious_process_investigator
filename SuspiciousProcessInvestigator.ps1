# ====================
# Suspicious Process Investigation Tool for Incident Responders
# Created by turt1e
# ====================

# --- OPTION 1: SAVE YOUR API KEY AS AN ENVIRONMNETAL VARIABLE AND REFERENCE HERE ---
$VirusTotalApiKey = $env:VT_API_KEY

## --- OPTION 2: DIRECTLY ASSIGN YOUR API KEY TO THE VARIABLE BELOW (NOT RECOMMENDED) ---
# $VirusTotalApiKey = "Insert_Your_VT_API_Key_Here"

Clear-Host

Write-Host "=== Suspicious Process Investigator by turt1e ===" -ForegroundColor Yellow

# --- Retrieve user input & if the process does not match the $processName variable, display error and close the application---
    $processName = Read-Host "Enter the suspicious process name. If not previously identified, this can be determined by using the Get-Process cmdlet"

    $processes = Get-Process -Name $processName -ErrorAction SilentlyContinue

if (-not $processes) {

    Write-Host "Process not found." -ForegroundColor Red
    exit
}

# --- VirusTotal Function to query API ---
function Get-VirusTotalHashReport {
    param (
        [Parameter(Mandatory)]
        [string]$SHA256,
        [string]$ApiKey
    )

    if (-not $ApiKey) {
        return @{ VT_Status = "API key not configured" }
    }

    try {
        $headers = @{
            "x-apikey" = $ApiKey
        }

        $uri = "https://www.virustotal.com/api/v3/files/$SHA256"
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers -ErrorAction Stop

        $stats = $response.data.attributes.last_analysis_stats

        return @{
            VT_Malicious   = $stats.malicious
            VT_Suspicious  = $stats.suspicious
            VT_Harmless    = $stats.harmless
            VT_Undetected  = $stats.undetected
            VT_Reputation  = $response.data.attributes.reputation
            VT_LastScan    = (Get-Date 1970-01-01).AddSeconds(
                                $response.data.attributes.last_analysis_date
                             ).ToString("o")
        }
    }
    catch {
        return @{ VT_Status = "Lookup failed or rate limited" }
    }
}

foreach ($proc in $processes) {

    Write-Host "`n--- Process Information ---" -ForegroundColor Yellow

# --- Retrieve process information & network connections ---
    $procInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)"

    $parentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($procInfo.ParentProcessId)"

    $childProcs = Get-CimInstance Win32_Process | Where-Object {
        $_.ParentProcessId -eq $proc.Id
    }

    $netConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
        $_.OwningProcess -eq $proc.Id
    }

# --- Retrieve file hash for target process and perform VirusTotal Hash Lookup ---
    $sha256Hash = "N/A"
    $vtResult = @{ VT_Status = "Not performed" }

    if ($procInfo.ExecutablePath -and (Test-Path $procInfo.ExecutablePath)) {
        try {
            $sha256Hash = (Get-FileHash -Path $procInfo.ExecutablePath -Algorithm SHA256).Hash
            $vtResult = Get-VirusTotalHashReport -SHA256 $sha256Hash -ApiKey $VirusTotalApiKey
        }
        catch {
            $sha256Hash = "Access denied or failed to hash"
        }
    }
    else {
        $sha256Hash = "Executable path unavailable"
    }

# --- Display all process information & VirusTotal scores ---
[PSCustomObject]@{
    ProcessName = $processName
    PID = $proc.Id
    Path = $procInfo.ExecutablePath
    ProcessFileHash = $sha256Hash
    ParentProcess = $parentProc.Name
    ParentPID = $parentProc.ProcessId
    VT_Malicious    = $vtResult.VT_Malicious
    VT_Suspicious   = $vtResult.VT_Suspicious
    VT_Reputation   = $vtResult.VT_Reputation
    VT_LastScan     = $vtResult.VT_LastScan
    VT_Status       = $vtResult.VT_Status
    } | Format-List

# --- Display child process information ---
    Write-Host "--- Child Processes ---" -ForegroundColor Yellow
    
if($childProcs) {
        $childProcs | Select-Object Name, ProcessId, ExecutablePath | Format-Table -AutoSize
    }
else {
        Write-Host "No child processes found." -ForegroundColor Red
    }

# --- Display network activity details ---
    Write-Host "`n--- Network Connections ---" -ForegroundColor Yellow

    if($netConnections) {
        $netConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
    } else {
        Write-Host "No active network connections found." -ForegroundColor Red
    }
}