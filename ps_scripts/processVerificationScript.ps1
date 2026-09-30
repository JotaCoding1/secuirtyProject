#Requires -Version 5.1
<#
.SYNOPSIS
    Snapshots every running process with all available details, triages the risky
    ones first, and exports everything to JSON and CSV. Uses only built-in cmdlets.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = '.',
    [switch]$SkipModules
)

$lolbins = @(
    'powershell.exe', 'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
    'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe'
)
$officeApps = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'onenote.exe')
$writablePaths = '(?i)\\(Users|AppData|Temp|ProgramData)\\'
$encodedCommand = '(?i)\s-e(nc\w*)?\s+[A-Za-z0-9+/=]{20,}'
$badSignatures = 'HashMismatch', 'NotTrusted'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Not running as Administrator: owners, paths and modules will be incomplete, and the missing-path rule is skipped.'
}

function Invoke-Safely {
    param([scriptblock]$Block)
    try { & $Block } catch { $null }
}

function ConvertTo-PlainValue {
    param($Value)
    if ($Value -is [datetime]) { $Value.ToString('o') } else { $Value }
}

function Get-ParentProcess {
    param($Cim)
    $parent = $cimById[[int]$Cim.ParentProcessId]
    if ($parent -and $parent.CreationDate -le $Cim.CreationDate) { $parent }
}

function Get-TriageReasons {
    param($Cim, [string]$ParentName)

    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($Cim.Name -in $lolbins) {
        $reasons.Add('Known LoLBin')
    }
    if ($Cim.ExecutablePath -match $writablePaths) {
        $reasons.Add('Runs from user-writable path')
    }
    elseif ($isAdmin -and [string]::IsNullOrWhiteSpace($Cim.ExecutablePath) -and $Cim.ProcessId -gt 4) {
        $reasons.Add('Missing executable path')
    }
    if ($Cim.CommandLine -match $encodedCommand) {
        $reasons.Add('Encoded command line')
    }
    if ($ParentName -in $officeApps -and $Cim.Name -in $lolbins) {
        $reasons.Add("Spawned by $ParentName")
    }

    return , $reasons
}

function Get-ProcessDetail {
    param($Item, [string]$Category)

    $cim = $Item.Cim
    $procId = [int]$cim.ProcessId
    $gp = $psById[$procId]
    $path = $cim.ExecutablePath
    $hasFile = $path -and (Test-Path -LiteralPath $path -PathType Leaf)

    $row = [ordered]@{
        TriageCategory  = $Category
        TriageReason    = $Item.Reasons -join '; '
        ProcessId       = $procId
        Name            = $cim.Name
        ParentProcessId = $cim.ParentProcessId
        ParentName      = $Item.ParentName
        Owner           = $null
    }

    $owner = Invoke-CimMethod -InputObject $cim -MethodName GetOwner -ErrorAction SilentlyContinue
    if ($owner.ReturnValue -eq 0) { $row.Owner = "$($owner.Domain)\$($owner.User)" }

    foreach ($prop in $cim.CimInstanceProperties) {
        if (-not $row.Contains($prop.Name)) { $row[$prop.Name] = ConvertTo-PlainValue $prop.Value }
    }

    $psProps = [ordered]@{
        Company         = 'Company'
        Product         = 'Product'
        ProductVersion  = 'ProductVersion'
        FileVersion     = 'FileVersion'
        FileDescription = 'Description'
        CpuSeconds      = 'CPU'
        StartTime       = 'StartTime'
        MainWindowTitle = 'MainWindowTitle'
        Responding      = 'Responding'
        PriorityClass   = 'PriorityClass'
    }
    foreach ($key in $psProps.Keys) {
        $row[$key] = ConvertTo-PlainValue (Invoke-Safely { $gp.($psProps[$key]) })
    }

    $row.SignatureStatus = $null
    $row.SignerSubject = $null
    $row.Sha256 = $null
    if ($hasFile) {
        if (-not $sigCache.ContainsKey($path)) {
            $sigCache[$path] = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue
        }
        if (-not $hashCache.ContainsKey($path)) {
            $hashCache[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        }
        $sig = $sigCache[$path]
        if ($sig) {
            $row.SignatureStatus = [string]$sig.Status
            $row.SignerSubject = $sig.SignerCertificate.Subject
        }
        $row.Sha256 = $hashCache[$path]
    }

    $row.Services = @($servicesByPid["$procId"] | ForEach-Object Name)
    $row.Connections = @(
        foreach ($c in $tcpByPid["$procId"]) {
            "TCP $($c.LocalAddress):$($c.LocalPort) -> $($c.RemoteAddress):$($c.RemotePort) $($c.State)"
        }
        foreach ($c in $udpByPid["$procId"]) {
            "UDP $($c.LocalAddress):$($c.LocalPort)"
        }
    )

    $modules = @()
    if (-not $SkipModules -and $gp) {
        $modules = @(Invoke-Safely { $gp.Modules | ForEach-Object FileName } | Where-Object { $_ })
    }
    $row.ModuleCount = if ($modules.Count) { $modules.Count } else { $null }
    $row.Modules = $modules

    [pscustomobject]$row
}

Write-Host 'Collecting process data...' -ForegroundColor Cyan

$cimProcesses = @(Get-CimInstance -ClassName Win32_Process)
$cimById = @{}
foreach ($p in $cimProcesses) { $cimById[[int]$p.ProcessId] = $p }

$psById = @{}
foreach ($p in Get-Process) { $psById[$p.Id] = $p }

$servicesByPid = Get-CimInstance -ClassName Win32_Service |
    Where-Object { $_.ProcessId -gt 0 } |
    Group-Object ProcessId -AsHashTable -AsString
$tcpByPid = Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Group-Object OwningProcess -AsHashTable -AsString
$udpByPid = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
    Group-Object OwningProcess -AsHashTable -AsString

$sigCache = @{}
$hashCache = @{}

# Stage 1: cheap triage from process metadata only, no disk access
$triaged = foreach ($cim in $cimProcesses) {
    $parentName = (Get-ParentProcess $cim).Name
    [pscustomobject]@{
        Cim        = $cim
        ParentName = $parentName
        Reasons    = Get-TriageReasons $cim $parentName
    }
}

$highItems = @($triaged | Where-Object { $_.Reasons.Count -gt 0 } | Sort-Object { $_.Cim.Name })
$restItems = @($triaged | Where-Object { $_.Reasons.Count -eq 0 } | Sort-Object { $_.Cim.Name })

# Stage 2: full analysis, high-priority first, then everything else
Write-Host "Analyzing $($highItems.Count) high-priority processes..." -ForegroundColor Yellow
$highRows = @($highItems | ForEach-Object { Get-ProcessDetail $_ 'High_Priority' })

Write-Host "Analyzing $($restItems.Count) remaining processes..." -ForegroundColor Cyan
$restRows = @($restItems | ForEach-Object { Get-ProcessDetail $_ 'Standard' })

# Stage 3: signature problems found during analysis promote a process to high priority
$promoted = @($restRows | Where-Object { $_.SignatureStatus -in $badSignatures })
foreach ($row in $promoted) {
    $row.TriageCategory = 'High_Priority'
    $row.TriageReason = "Invalid signature ($($row.SignatureStatus))"
}
$highRows = @($highRows) + $promoted
$restRows = @($restRows | Where-Object { $_.TriageCategory -eq 'Standard' })

$null = New-Item -ItemType Directory -Path $OutputDir -Force
$stamp = Get-Date -Format 'yyyyMMdd_HHmm'
$jsonPath = Join-Path $OutputDir "ProcessSnapshot_$stamp.json"
$csvPath = Join-Path $OutputDir "ProcessSnapshot_$stamp.csv"

[ordered]@{
    GeneratedAt        = (Get-Date).ToString('o')
    ComputerName       = $env:COMPUTERNAME
    RanAsAdministrator = $isAdmin
    Counts             = [ordered]@{
        HighPriority = $highRows.Count
        Standard     = $restRows.Count
        Total        = $highRows.Count + $restRows.Count
    }
    HighPriority       = $highRows
    Standard           = $restRows
} | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8

# CSV is flat, so list-valued fields are joined into a single cell
($highRows + $restRows) | ForEach-Object {
    $flat = [ordered]@{}
    foreach ($prop in $_.PSObject.Properties) {
        $flat[$prop.Name] = if ($prop.Value -is [array]) { $prop.Value -join '; ' } else { $prop.Value }
    }
    [pscustomobject]$flat
} | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host "High-priority processes ($($highRows.Count)):" -ForegroundColor Yellow
$highRows | Format-Table ProcessId, Name, TriageReason -AutoSize
Write-Host "Standard processes: $($restRows.Count)"
Write-Host "Saved to $jsonPath and $csvPath" -ForegroundColor Green