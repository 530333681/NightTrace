<#
.SYNOPSIS
    NightTrace Collector - read-only Windows host artifact collector.

.DESCRIPTION
    Collects two categories of artifacts using built-in Windows capabilities only:
      * Processes        (name / PID / PPID / start time / image path / command line / owner)
      * Persistence      (Run+RunOnce registry keys, scheduled tasks, Windows services)

    Design notes:
      * READ-ONLY. Nothing on the target system is modified, installed or configured.
      * Every module runs in its own try/catch. A failing module never aborts the run.
      * Results are written to a temporary work directory as JSON + CSV, together with
        collection_meta.json (collect time, per-module status, errors).
      * The work directory is finally compressed into a timestamped ZIP file.

    NOT implemented on purpose (do not assume these exist):
      * No timeline / network / threat-intel / registry-last-write-time collection.
      * No hidden persistence, no remote execution, no privilege escalation,
        no security-product evasion.

.PARAMETER OutputDir
    Base directory used for the temporary work folder. Default: %TEMP%\NightTrace

.PARAMETER ZipPath
    Optional full path for the produced ZIP file. Default: <AgentWorkDir of the caller>
    falls back to the user's Desktop when no explicit path is given.

.PARAMETER KeepWorkDir
    Keep the intermediate work directory after the ZIP has been created.

.PARAMETER NoZip
    Skip ZIP creation entirely (useful for debugging). The work directory path is printed.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\collector.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\collector.ps1 -OutputDir D:\IRTriage -ZipPath D:\evidence.zip
#>

[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path $env:TEMP 'NightTrace'),
    [string]$ZipPath,
    [switch]$KeepWorkDir,
    [switch]$NoZip
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'   # keep the console output clean
$ScriptVersion = '1.0.0'

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------
function Write-Banner {
    Write-Host ''
    Write-Host '  _   _ _       _     _____                 ' -ForegroundColor Green
    Write-Host ' | \ | (_) __ _| |__ |_   _| __ __ _  ___ ___' -ForegroundColor Green
    Write-Host ' |  \| | |/ _` | ''_ \  | || ''__/ _` |/ __/ _ \' -ForegroundColor Green
    Write-Host ' | |\  | | (_| | | | | | || | | (_| | (_|  __/' -ForegroundColor Green
    Write-Host ' |_| \_|_|\__, |_| |_| |_||_|  \__,_|\___\___|' -ForegroundColor Green
    Write-Host '          |___/   read-only host artifact collector' -ForegroundColor DarkGray
    Write-Host "          v$ScriptVersion  |  defensive IR demo  |  no system changes" -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Step  { param([string]$m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok    { param([string]$m) Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err   { param([string]$m) Write-Host "[x] $m" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-Utf8File {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)   # UTF-8 without BOM
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Write-JsonFile {
    param([string]$Path, $Items, [int]$Depth = 6)
    $arr = @($Items)
    if ($arr.Count -eq 0) {
        $json = '[]'
    } else {
        $json = ConvertTo-Json -InputObject $arr -Depth $Depth
        # Windows PowerShell 5.1 collapses single-element arrays; fix that explicitly.
        if ($arr.Count -eq 1 -and $json.TrimStart()[0] -ne '[') { $json = "[$json]" }
    }
    Write-Utf8File -Path $Path -Content $json
}

function Write-CsvFile {
    param([string]$Path, $Items)
    $arr = @($Items)
    if ($arr.Count -eq 0) {
        Write-Utf8File -Path $Path -Content ''
        return
    }
    $csv = $arr | ConvertTo-Csv -NoTypeInformation
    Write-Utf8File -Path $Path -Content ($csv -join "`r`n")
}

function ConvertTo-IsoString {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-ddTHH:mm:sszzz') }
        $d = [datetime]$Value
        return $d.ToString('yyyy-MM-ddTHH:mm:sszzz')
    } catch { return [string]$Value }
}

$script:Health = New-Object System.Collections.ArrayList
$script:Notes  = New-Object System.Collections.ArrayList

function Add-Note {
    param([string]$Text)
    [void]$script:Notes.Add($Text)
    Write-Warn2 "  $Text"
}

function Invoke-Module {
    param(
        [string]$Name,
        [string]$JsonName,
        [string]$CsvName,
        [scriptblock]$Body
    )
    Write-Step "Module: $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'ok'
    $errorMessage = $null
    $rows = $null
    try {
        $rows = @(& $Body)
    } catch {
        $status = 'failed'
        $errorMessage = $_.Exception.Message
        $rows = @()
        Write-Err "  $Name failed: $errorMessage"
    }
    $sw.Stop()

    $count = @($rows).Count
    if ($status -eq 'ok') {
        Write-Ok ("  {0} -> {1} record(s) in {2} ms" -f $Name, $count, $sw.ElapsedMilliseconds)
    }

    $jsonPath = Join-Path $script:WorkDir $JsonName
    $csvPath  = Join-Path $script:WorkDir $CsvName
    try {
        Write-JsonFile -Path $jsonPath -Items $rows
        Write-CsvFile  -Path $csvPath  -Items $rows
    } catch {
        Write-Warn2 "  could not write $JsonName : $($_.Exception.Message)"
        $errorMessage = "$errorMessage | write error: $($_.Exception.Message)"
    }

    [void]$script:Health.Add([pscustomobject][ordered]@{
        module         = $Name
        status         = $status
        recordCount    = $count
        durationMs     = $sw.ElapsedMilliseconds
        jsonFile       = $JsonName
        csvFile        = $CsvName
        error          = $errorMessage
    })
}

# ---------------------------------------------------------------------------
# Collector bodies
# ---------------------------------------------------------------------------
function Collect-SystemInfo {
    $os = $null; $cs = $null
    try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop } catch { }
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch { }

    $whoAmI = $null
    try { $whoAmI = (whoami) 2>$null } catch { }

    [pscustomobject][ordered]@{
        ComputerName     = $env:COMPUTERNAME
        UserName         = $env:USERNAME
        WhoAmI           = $whoAmI
        OSName           = $os.Caption
        OSVersion        = $os.Version
        OSBuild          = $os.BuildNumber
        OSArchitecture   = $os.OSArchitecture
        InstallDate      = ConvertTo-IsoString $os.InstallDate
        LastBootUpTime   = ConvertTo-IsoString $os.LastBootUpTime
        Manufacturer     = $cs.Manufacturer
        Model            = $cs.Model
        Domain           = $cs.Domain
        TotalMemoryMB    = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1MB) } else { $null }
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsElevated       = $null
        CollectorVersion = $ScriptVersion
    } | ForEach-Object {
        try {
            $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($identity)
            $_.IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { }
        $_
    }
}

function Get-ProcessOwnerMap {
    <#
      Returns @{ Map = <hashtable pid->user>; Source = <string>; Error = <string> }.
      Owner lookup needs elevation on most systems; we try several built-in
      methods and degrade gracefully instead of failing the module.
    #>
    $map = @{}
    $errors = @()

    # 1) CIM with -IncludeUserName (fastest when available)
    try {
        $withUser = @(Get-CimInstance -ClassName Win32_Process -IncludeUserName -ErrorAction Stop)
        foreach ($p in $withUser) { if ($p.UserName) { $map[[int]$p.ProcessId] = $p.UserName } }
        if ($map.Count -gt 0) {
            return @{ Map = $map; Source = 'CIM Win32_Process -IncludeUserName'; Error = $null }
        }
    } catch { $errors += "CIM -IncludeUserName: $($_.Exception.Message)" }

    # 2) Get-Process -IncludeUserName
    try {
        $gp = @(Get-Process -IncludeUserName -ErrorAction Stop)
        foreach ($p in $gp) { if ($p.UserName) { $map[[int]$p.Id] = $p.UserName } }
        if ($map.Count -gt 0) {
            return @{ Map = $map; Source = 'Get-Process -IncludeUserName'; Error = ($errors -join ' | ') }
        }
    } catch { $errors += "Get-Process -IncludeUserName: $($_.Exception.Message)" }

    return @{ Map = $map; Source = $null; Error = ($errors -join ' | ') }
}

function Collect-Processes {
    $procs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)

    $ownerInfo = Get-ProcessOwnerMap
    $owners = $ownerInfo.Map
    $script:OwnerSource = $ownerInfo.Source
    if ($ownerInfo.Source) {
        Write-Host "  [i] process owner source: $($ownerInfo.Source) ($($owners.Count) resolved)" -ForegroundColor DarkGray
    } else {
        Add-Note 'process owner (UserName) could not be collected - run collector.ps1 elevated to get it'
    }

    $nameById = @{}
    foreach ($p in $procs) { $nameById[[int]$p.ProcessId] = $p.Name }

    $rows = New-Object System.Collections.ArrayList
    foreach ($p in $procs) {
        $pid_ = [int]$p.ProcessId
        $ppid = [int]$p.ParentProcessId
        $parentName = $null
        if ($nameById.ContainsKey($ppid)) { $parentName = $nameById[$ppid] }

        $owner = $null
        if ($owners.ContainsKey($pid_)) { $owner = $owners[$pid_] }

        [void]$rows.Add([pscustomobject][ordered]@{
            Name             = $p.Name
            ProcessId        = $pid_
            ParentProcessId  = $ppid
            ParentName       = $parentName
            CreationDate     = ConvertTo-IsoString $p.CreationDate
            ExecutablePath   = $p.ExecutablePath
            CommandLine      = $p.CommandLine
            UserName         = $owner
            SessionId        = $p.SessionId
        })
    }
    return $rows
}

function Collect-RunKeys {
    # NOTE: inside the Registry provider a hive must be spelled out in full
    # (Registry::HKEY_CURRENT_USER\...). The short aliases HKCU:/HKLM: are only
    # valid as PSDrive paths, so we keep a separate full-name map.
    $hiveRoot = @{
        'HKLM' = 'HKEY_LOCAL_MACHINE'
        'HKCU' = 'HKEY_CURRENT_USER'
        'HKU'  = 'HKEY_USERS'
    }

    $keys = @(
        @{ Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';          Scope = 'Machine' },
        @{ Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';      Scope = 'Machine' },
        @{ Hive = 'HKLM'; Path = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run';     Scope = 'Machine (32-bit view)' },
        @{ Hive = 'HKLM'; Path = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Scope = 'Machine (32-bit view)' },
        @{ Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run';          Scope = 'Current user' },
        @{ Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';      Scope = 'Current user' }
    )

    # Loaded user hives (HKEY_USERS) - one profile per loaded SID.
    $sids = @()
    try {
        $sids = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction Stop |
                  Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
                  Select-Object -ExpandProperty PSChildName)
    } catch {
        # Fall back to the .NET API, which does not need the PS provider.
        try {
            $sids = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-' })
            if ($sids.Count -gt 0) { Add-Note "HKEY_USERS read through the .NET Registry API (provider access denied)" }
        } catch {
            Add-Note "HKEY_USERS could not be enumerated: $($_.Exception.Message)"
        }
    }
    foreach ($sid in $sids) {
        $keys += @{ Hive = 'HKU'; Path = "$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";     Scope = "User hive {$sid}" }
        $keys += @{ Hive = 'HKU'; Path = "$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Scope = "User hive {$sid}" }
    }

    # Map SID -> account name for readability (best effort).
    $sidToName = @{}
    try {
        foreach ($u in @(Get-CimInstance -ClassName Win32_UserAccount -ErrorAction Stop)) {
            $sidToName[$u.SID] = "$($u.Domain)\$($u.Name)"
        }
    } catch { }

    $rows = New-Object System.Collections.ArrayList
    $found = 0
    foreach ($k in $keys) {
        $psPath = "Registry::$($hiveRoot[$k.Hive])\$($k.Path)"
        try {
            if (-not (Test-Path -LiteralPath $psPath)) { continue }
            $props = Get-ItemProperty -LiteralPath $psPath -ErrorAction Stop
            $names = @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })
            $found++
            if ($names.Count -eq 0) {
                [void]$rows.Add([pscustomobject][ordered]@{
                    Type = 'Registry Run Key'; Hive = $k.Hive; KeyPath = $k.Path; Scope = $k.Scope
                    Name = '(key present, no values)'; Command = $null; ValueType = $null
                    RunAs = (Resolve-Sid $k.Scope $sidToName); LastWriteTime = $null
                    CollectedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
                })
                continue
            }
            foreach ($p in $names) {
                $valueType = $null
                try { $valueType = (Get-Item -LiteralPath $psPath).GetValueKind($p.Name).ToString() } catch { }
                [void]$rows.Add([pscustomobject][ordered]@{
                    Type        = 'Registry Run Key'
                    Hive        = $k.Hive
                    KeyPath     = $k.Path
                    Scope       = $k.Scope
                    Name        = $p.Name
                    Command     = [string]$p.Value
                    ValueType   = $valueType
                    RunAs       = (Resolve-Sid $k.Scope $sidToName)
                    # Not implemented in v1: registry key last-write time requires RegQueryInfoKey P/Invoke.
                    LastWriteTime = $null
                    CollectedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
                })
            }
        } catch {
            Write-Warn2 "  run key read failed ($($k.Hive)\$($k.Path)): $($_.Exception.Message)"
        }
    }
    if ($found -eq 0) {
        Add-Note 'none of the Run/RunOnce registry keys could be opened - the collector may be running under a restricted token'
    }
    return $rows
}

function Resolve-Sid {
    param([string]$Scope, [hashtable]$Map)
    if ($null -eq $Scope) { return $null }
    if ($Scope -match '^\s*User hive\s+') {
        $sid = ($Scope -replace '.*\{(.*)\}.*', '$1')
        if ($Map -and $Map.ContainsKey($sid)) { return $Map[$sid] }
        return $sid
    }
    return $Scope
}

function Collect-ScheduledTasks {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    $rows = New-Object System.Collections.ArrayList
    foreach ($t in $tasks) {
        $info = $null
        try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { }

        $actions = @()
        foreach ($a in @($t.Actions)) {
            $actionClass = ''
            try { $actionClass = [string]$a.CimClass.CimClassName } catch { }

            # COM handler actions carry a ClassId instead of an executable path.
            if ($actionClass -eq 'MSFT_TaskComHandlerAction') {
                $actions += "COM handler (ClassId: $($a.ClassId))"
                continue
            }

            $parts = @()
            if ($a.Execute) { $parts += $a.Execute }
            if ($a.Arguments) { $parts += $a.Arguments }
            if ($a.WorkingDirectory) { $parts += "(wd: $($a.WorkingDirectory))" }
            if ($parts.Count -gt 0) { $actions += ($parts -join ' ') }
        }

        $triggers = @()
        foreach ($tr in @($t.Triggers)) {
            $desc = $tr.CimClass.CimClassName -replace '^MSFT_Task', '' -replace 'Trigger$', ''
            if ($tr.StartBoundary) { $desc += " @ $($tr.StartBoundary)" }
            if ($tr.Repetition -and $tr.Repetition.Interval) { $desc += " every $($tr.Repetition.Interval)" }
            $triggers += $desc
        }

        # Principal.UserId is sometimes a non-resolvable placeholder ("1") for tasks
        # whose principal is a group. Keep the raw values and report RunAs as null
        # rather than presenting a meaningless account name.
        $runAsRaw = [string]$t.Principal.UserId
        $groupId  = [string]$t.Principal.GroupId
        $runAs    = $runAsRaw
        if ([string]::IsNullOrWhiteSpace($runAs) -or $runAs -match '^\d+$') { $runAs = $null }

        [void]$rows.Add([pscustomobject][ordered]@{
            Type           = 'Scheduled Task'
            TaskName       = $t.TaskName
            TaskPath       = $t.TaskPath
            FullName       = "$($t.TaskPath)$($t.TaskName)"
            State          = [string]$t.State
            Author         = $t.Author
            RunAs          = $runAs
            RunAsRaw       = $runAsRaw
            GroupId        = if ($groupId) { $groupId } else { $null }
            RunLevel       = [string]$t.Principal.RunLevel
            LogonType      = [string]$t.Principal.LogonType
            Execute        = ($actions -join ' || ')
            Triggers       = ($triggers -join ' || ')
            LastRunTime    = if ($info) { ConvertTo-IsoString $info.LastRunTime } else { $null }
            NextRunTime    = if ($info) { ConvertTo-IsoString $info.NextRunTime } else { $null }
            LastTaskResult = if ($info) { $info.LastTaskResult } else { $null }
            MissedRuns     = if ($info) { $info.NumberOfMissedRuns } else { $null }
            Description    = $t.Description
            Source         = $t.Source
            CollectedAt    = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        })
    }
    return $rows
}

function Collect-Services {
    $svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    $rows = New-Object System.Collections.ArrayList
    foreach ($s in $svcs) {
        [void]$rows.Add([pscustomobject][ordered]@{
            Type        = 'Windows Service'
            Name        = $s.Name
            DisplayName = $s.DisplayName
            State       = $s.State
            StartMode   = $s.StartMode
            RunAs       = $s.StartName
            Execute     = $s.PathName
            ProcessId   = $s.ProcessId
            ServiceType = $s.ServiceType
            ExitCode    = $s.ExitCode
            Description = $s.Description
            CollectedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
        })
    }
    return $rows
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Banner

$startTime = Get-Date
$stamp     = $startTime.ToString('yyyyMMdd_HHmmss')

$script:WorkDir = Join-Path $OutputDir "NightTrace_$($env:COMPUTERNAME)_$stamp"
try {
    New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
} catch {
    Write-Err "Cannot create work directory '$($script:WorkDir)': $($_.Exception.Message)"
    exit 1
}
Write-Ok "Work directory: $($script:WorkDir)"
Write-Host ''

# --- module 1: system info ------------------------------------------------
Write-Step 'Module: SystemInfo'
$swSys = [System.Diagnostics.Stopwatch]::StartNew()
$systemInfo = @()
$sysStatus = 'ok'; $sysError = $null
try {
    $systemInfo = @(Collect-SystemInfo)
} catch {
    $sysStatus = 'failed'; $sysError = $_.Exception.Message
    Write-Err "  SystemInfo failed: $sysError"
}
$swSys.Stop()
if ($systemInfo.Count -gt 0) { Write-Ok "  SystemInfo -> 1 record in $($swSys.ElapsedMilliseconds) ms" }
try { Write-JsonFile -Path (Join-Path $script:WorkDir 'system_info.json') -Items $systemInfo } catch {
    Write-Warn2 "  could not write system_info.json: $($_.Exception.Message)"
}
[void]$script:Health.Add([pscustomobject][ordered]@{
    module = 'SystemInfo'; status = $sysStatus; recordCount = $systemInfo.Count
    durationMs = $swSys.ElapsedMilliseconds; jsonFile = 'system_info.json'; csvFile = $null; error = $sysError
})
Write-Host ''

# --- module 2: processes --------------------------------------------------
Invoke-Module -Name 'Processes' -JsonName 'processes.json' -CsvName 'processes.csv' -Body { Collect-Processes }
Write-Host ''

# --- module 3: persistence ------------------------------------------------
Invoke-Module -Name 'PersistenceRunKeys' -JsonName 'persistence_run.json' -CsvName 'persistence_run.csv' -Body { Collect-RunKeys }
Write-Host ''
Invoke-Module -Name 'PersistenceScheduledTasks' -JsonName 'persistence_scheduled_tasks.json' -CsvName 'persistence_scheduled_tasks.csv' -Body { Collect-ScheduledTasks }
Write-Host ''
Invoke-Module -Name 'PersistenceServices' -JsonName 'persistence_services.json' -CsvName 'persistence_services.csv' -Body { Collect-Services }
Write-Host ''

# --- metadata -------------------------------------------------------------
$endTime = Get-Date
$meta = [ordered]@{
    tool              = 'NightTrace Collector'
    version           = $ScriptVersion
    accessMode        = 'read-only'
    startedAt         = $startTime.ToString('yyyy-MM-ddTHH:mm:sszzz')
    finishedAt        = $endTime.ToString('yyyy-MM-ddTHH:mm:sszzz')
    durationSeconds   = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    computerName      = $env:COMPUTERNAME
    user              = $env:USERNAME
    elevated          = $null
    workDirectory     = $script:WorkDir
    processOwnerSource = $script:OwnerSource
    notes             = @($script:Notes)
    modules           = @($script:Health)
    recordCounts      = [ordered]@{
        processes           = (@($script:Health | Where-Object { $_.module -eq 'Processes' }).recordCount)
        persistenceRunKeys  = (@($script:Health | Where-Object { $_.module -eq 'PersistenceRunKeys' }).recordCount)
        scheduledTasks      = (@($script:Health | Where-Object { $_.module -eq 'PersistenceScheduledTasks' }).recordCount)
        services            = (@($script:Health | Where-Object { $_.module -eq 'PersistenceServices' }).recordCount)
    }
    notImplemented    = @(
        'registry key last-write time',
        'timeline / network connections / threat intel / hash lookup',
        'file-system, logon and USB artifact collection'
    )
}
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $meta['elevated'] = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
Write-Utf8File -Path (Join-Path $script:WorkDir 'collection_meta.json') -Content ($meta | ConvertTo-Json -Depth 6)

# --- package --------------------------------------------------------------
Write-Host ''
Write-Host '---------------- collection summary ----------------' -ForegroundColor DarkGray
foreach ($h in $script:Health) {
    $color = if ($h.status -eq 'ok') { 'Green' } else { 'Red' }
    Write-Host ("  {0,-30} {1,-8} {2,6} record(s)  {3,6} ms" -f $h.module, $h.status.ToUpper(), $h.recordCount, $h.durationMs) -ForegroundColor $color
    if ($h.error) { Write-Warn2 "      error: $($h.error)" }
}
Write-Host '----------------------------------------------------' -ForegroundColor DarkGray

$failed = @($script:Health | Where-Object { $_.status -ne 'ok' })
if ($failed.Count -gt 0) {
    Write-Warn2 "$($failed.Count) module(s) failed - the rest of the package is still usable."
}

if ($NoZip) {
    Write-Host ''
    Write-Ok "NoZip specified. Work directory kept at: $($script:WorkDir)"
    exit 0
}

Write-Host ''
Write-Step 'Packaging results into ZIP ...'
if (-not $ZipPath) {
    $ZipPath = Join-Path $OutputDir "NightTrace_$($env:COMPUTERNAME)_$stamp.zip"
}
$zipDir = Split-Path -Parent $ZipPath
if ($zipDir -and -not (Test-Path -LiteralPath $zipDir)) {
    New-Item -ItemType Directory -Path $zipDir -Force | Out-Null
}
if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }

try {
    # .NET ZipFile produces no progress noise and handles non-ASCII names better
    # than the PowerShell 5.1 Compress-Archive implementation.
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $script:WorkDir,
        $ZipPath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false)
    $sizeKb = [math]::Round((Get-Item -LiteralPath $ZipPath).Length / 1KB, 1)
    Write-Ok "ZIP created: $ZipPath ($sizeKb KB)"
} catch {
    Write-Warn2 "  .NET ZipFile failed ($($_.Exception.Message)) - falling back to Compress-Archive"
    try {
        Compress-Archive -Path (Join-Path $script:WorkDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal -ErrorAction Stop
        $sizeKb = [math]::Round((Get-Item -LiteralPath $ZipPath).Length / 1KB, 1)
        Write-Ok "ZIP created: $ZipPath ($sizeKb KB)"
    } catch {
        Write-Err "ZIP creation failed: $($_.Exception.Message)"
        Write-Warn2 "Raw results are still available in: $($script:WorkDir)"
        exit 2
    }
}

if (-not $KeepWorkDir) {
    try { Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction Stop } catch {
        Write-Warn2 "Could not remove work directory: $($_.Exception.Message)"
    }
} else {
    Write-Host "[i] Work directory kept: $($script:WorkDir)" -ForegroundColor DarkGray
}

Write-Host ''
Write-Ok "Collection finished in $([math]::Round(($endTime - $startTime).TotalSeconds, 2)) s"
Write-Host "ZIP_FILE=$ZipPath" -ForegroundColor Green
Write-Host ''
Write-Host 'Next step: start the web UI (python app.py) and upload this ZIP.' -ForegroundColor DarkGray
Write-Host ''
