#Requires -Version 5.1
<##
.SYNOPSIS
    Snapshots Windows services with available details, triages risky services first,
    and exports everything to JSON and CSV. Uses only built-in cmdlets.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = '.',
    [switch]$SkipNetworkConnections
)

$writablePaths = '(?i)\\(Users|AppData|Temp|ProgramData)\\'
$systemAccounts = @('LocalSystem', 'NT AUTHORITY\LocalSystem', 'LocalService', 'NT AUTHORITY\LocalService', 'NetworkService', 'NT AUTHORITY\NetworkService')
$badSignatures = @('HashMismatch', 'NotTrusted')

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not running as Administrator: service details, owners and connections may be incomplete.'
}

function Invoke-Safely {
    param([scriptblock]$Block)
    try { & $Block } catch { $null }
}

function ConvertTo-PlainValue {
    param($Value)
    if ($Value -is [datetime]) { $Value.ToString('o') } else { $Value }
}

function Get-ServiceExecutablePath {
    param([string]$PathName)

    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    if ($PathName -match '^\s*"([^"]+)"') { return $Matches[1] }
    if (Test-Path -LiteralPath $PathName -PathType Leaf) { return $PathName }
    if ($PathName -match '^\s*(.*?\.exe)(?:\s|$)') { return $Matches[1].Trim() }
    return ($PathName -split '\s+', 2)[0]
}

function Get-ServiceTriageReasons {
    param($Service, [string]$ExecutablePath, $Process)

    $reasons = [System.Collections.Generic.List[string]]::new()
    $pathName = [string]$Service.PathName

    if ($Service.StartMode -eq 'Auto' -and $Service.State -eq 'Running' -and $Service.StartName -notin $systemAccounts) {
        $reasons.Add('Automatic service runs under a non-system account')
    }
    if ($ExecutablePath -match $writablePaths) {
        $reasons.Add('Executable runs from a user-writable path')
    }
    if ($pathName -and $pathName -notmatch '^\s*"' -and $ExecutablePath -match '\s') {
        $reasons.Add('Unquoted service path')
    }
    if ($Service.StartMode -eq 'Auto' -and -not (Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
        $reasons.Add('Automatic service executable is missing')
    }
    if ($Service.State -eq 'Running' -and $Service.ProcessId -gt 0 -and -not $Process) {
        $reasons.Add('Running service process could not be inspected')
    }
    if ($Service.StartMode -eq 'Auto' -and $Service.ServiceType -match 'Own Process' -and $Service.StartName -notin $systemAccounts -and $Service.PathName -match '(?i)(powershell|cmd|wscript|cscript|mshta|rundll32)') {
        $reasons.Add('Automatic service uses a command interpreter')
    }

    return , $reasons
}

function Get-ServiceDetail {
    param($Item, [string]$Category)

    $service = $Item.Service
    $path = $Item.ExecutablePath
    $process = $Item.Process
    $processId = [int]$service.ProcessId
    $hasFile = $path -and (Test-Path -LiteralPath $path -PathType Leaf)

    $row = [ordered]@{
        TriageCategory  = $Category
        TriageReason    = $Item.Reasons -join '; '
        Name            = $service.Name
        DisplayName     = $service.DisplayName
        State           = $service.State
        StartMode       = $service.StartMode
        StartName       = $service.StartName
        ServiceType     = $service.ServiceType
        ProcessId       = $processId
        ExecutablePath  = $path
        SignatureStatus = $null
        SignerSubject   = $null
        Sha256          = $null
    }

    foreach ($property in $service.CimInstanceProperties) {
        if (-not $row.Contains($property.Name)) {
            $row[$property.Name] = ConvertTo-PlainValue $property.Value
        }
    }

    if ($process) {
        $row.ProcessName = $process.Name
        $row.ProcessCommandLine = $process.CommandLine
        $row.ProcessOwner = $null
        $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction SilentlyContinue
        if ($owner.ReturnValue -eq 0) { $row.ProcessOwner = "$($owner.Domain)\$($owner.User)" }
    }

    if ($hasFile) {
        if (-not $sigCache.ContainsKey($path)) {
            $sigCache[$path] = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue
        }
        if (-not $hashCache.ContainsKey($path)) {
            $hashCache[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
        $signature = $sigCache[$path]
        if ($signature) {
            $row.SignatureStatus = [string]$signature.Status
            $row.SignerSubject = $signature.SignerCertificate.Subject
        }
        $row.Sha256 = $hashCache[$path]
    }

    $row.Dependencies = @($service.Dependencies)
    $row.Connections = @()
    if (-not $SkipNetworkConnections -and $processId -gt 0) {
        $row.Connections = @(
            foreach ($connection in $tcpByPid["$processId"]) {
                "TCP $($connection.LocalAddress):$($connection.LocalPort) -> $($connection.RemoteAddress):$($connection.RemotePort) $($connection.State)"
            }
            foreach ($connection in $udpByPid["$processId"]) {
                "UDP $($connection.LocalAddress):$($connection.LocalPort)"
            }
        )
    }

    [pscustomobject]$row
}

Write-Host 'Collecting service data...' -ForegroundColor Cyan

$services = @(Get-CimInstance -ClassName Win32_Service)
$processesById = @{}
foreach ($process in Get-CimInstance -ClassName Win32_Process) {
    $processesById[[int]$process.ProcessId] = $process
}

$tcpByPid = @{}
$udpByPid = @{}
if (-not $SkipNetworkConnections) {
    $tcpByPid = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Group-Object OwningProcess -AsHashTable -AsString
    $udpByPid = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Group-Object OwningProcess -AsHashTable -AsString
}

$sigCache = @{}
$hashCache = @{}

# Stage 1: cheap triage from service metadata before signature and hash checks.
$triaged = foreach ($service in $services) {
    $path = Get-ServiceExecutablePath $service.PathName
    $process = $processesById[[int]$service.ProcessId]
    [pscustomobject]@{
        Service         = $service
        ExecutablePath  = $path
        Process         = $process
        Reasons         = Get-ServiceTriageReasons $service $path $process
    }
}

$highItems = @($triaged | Where-Object { $_.Reasons.Count -gt 0 } | Sort-Object { $_.Service.Name })
$restItems = @($triaged | Where-Object { $_.Reasons.Count -eq 0 } | Sort-Object { $_.Service.Name })

# Stage 2: full analysis, high-priority services first, then everything else.
Write-Host "Analyzing $($highItems.Count) high-priority services..." -ForegroundColor Yellow
$highRows = @($highItems | ForEach-Object { Get-ServiceDetail $_ 'High_Priority' })

Write-Host "Analyzing $($restItems.Count) remaining services..." -ForegroundColor Cyan
$restRows = @($restItems | ForEach-Object { Get-ServiceDetail $_ 'Standard' })

# Stage 3: signature problems found during analysis promote a service to high priority.
$promoted = @($restRows | Where-Object { $_.SignatureStatus -in $badSignatures })
foreach ($row in $promoted) {
    $row.TriageCategory = 'High_Priority'
    $row.TriageReason = "Invalid signature ($($row.SignatureStatus))"
}
$highRows = @($highRows) + $promoted
$restRows = @($restRows | Where-Object { $_.TriageCategory -eq 'Standard' })

$null = New-Item -ItemType Directory -Path $OutputDir -Force
$stamp = Get-Date -Format 'yyyyMMdd_HHmm'
$jsonPath = Join-Path $OutputDir "ServiceSnapshot_$stamp.json"
$csvPath = Join-Path $OutputDir "ServiceSnapshot_$stamp.csv"

[ordered]@{
    GeneratedAt        = (Get-Date).ToString('o')
    ComputerName       = $env:COMPUTERNAME
    RanAsAdministrator  = $isAdmin
    Counts             = [ordered]@{
        HighPriority = $highRows.Count
        Standard     = $restRows.Count
        Total        = $highRows.Count + $restRows.Count
    }
    HighPriority       = $highRows
    Standard           = $restRows
} | ConvertTo-Json -Depth 6 | Out-File -FilePath $jsonPath -Encoding UTF8

# CSV is flat, so list-valued fields are joined into a single cell.
($highRows + $restRows) | ForEach-Object {
    $flat = [ordered]@{}
    foreach ($property in $_.PSObject.Properties) {
        $flat[$property.Name] = if ($property.Value -is [array]) { $property.Value -join '; ' } else { $property.Value }
    }
    [pscustomobject]$flat
} | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host "High-priority services ($($highRows.Count)):" -ForegroundColor Yellow
$highRows | Format-Table Name, DisplayName, State, TriageReason -AutoSize
Write-Host "Standard services: $($restRows.Count)"
Write-Host "Saved to $jsonPath and $csvPath" -ForegroundColor Green
