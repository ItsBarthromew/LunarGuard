param(
    [int]$LookbackMinutes = 20,
    [string]$OutputDir = "C:\ProgramData\LunarGuard\filters",
    [switch]$Include4732,
    [switch]$ShowBaseline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# These events are always forwarded and never suppressed.
$CriticalSecurityEventIds = @(
    4625, # Failed login attempts
    4720, # New user account creation
    4728, # User added to privileged global group
    1102  # Audit log cleared
)

if ($Include4732) {
    # Useful add-on for local Administrators group membership changes.
    $CriticalSecurityEventIds += 4732
}

# High-volume process create noise seen on most Windows systems.
$NoisyProcessImages = @(
    "C:\Windows\System32\svchost.exe",
    "C:\Windows\System32\taskhostw.exe",
    "C:\Windows\System32\RuntimeBroker.exe",
    "C:\Windows\System32\WmiPrvSE.exe",
    "C:\Windows\System32\dllhost.exe",
    "C:\Windows\explorer.exe",
    "C:\Windows\System32\SearchIndexer.exe"
)

function Get-SysmonEvent1Baseline {
    param(
        [datetime]$StartTime,
        [string[]]$TargetImages
    )

    $result = [ordered]@{}
    foreach ($img in $TargetImages) {
        $result[$img] = 0
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Microsoft-Windows-Sysmon/Operational"
            Id        = 1
            StartTime = $StartTime
        } -ErrorAction Stop

        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()
            $imageNode = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" } | Select-Object -First 1
            if ($null -ne $imageNode) {
                $imgVal = [string]$imageNode."#text"
                if ($result.Contains($imgVal)) {
                    $result[$imgVal]++
                }
            }
        }
    }
    catch {
        Write-Warning "Could not query Sysmon baseline. Is Sysmon installed and logging enabled?"
    }

    return $result
}

$startTime = (Get-Date).AddMinutes(-1 * [math]::Abs($LookbackMinutes))

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$imageSuppressClauses = ($NoisyProcessImages | ForEach-Object {
    "(Data[@Name='Image']='$($_)')"
}) -join " or "

$criticalExpr = ($CriticalSecurityEventIds | Sort-Object -Unique | ForEach-Object {
    "EventID=$($_)"
}) -join " or "

$queryXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[($criticalExpr)]]</Select>
  </Query>

  <Query Id="1" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
    <Suppress Path="Microsoft-Windows-Sysmon/Operational">
      *[System[(EventID=1)] and EventData[($imageSuppressClauses)]]
    </Suppress>
  </Query>

  <Query Id="2" Path="System">
    <Select Path="System">*</Select>
    <Suppress Path="System">*[System[(EventID=16394)]]</Suppress>
  </Query>
</QueryList>
"@

# Safety assertion: critical IDs must never be in any suppress block.
foreach ($id in ($CriticalSecurityEventIds | Sort-Object -Unique)) {
    if ($queryXml -match "<Suppress[\s\S]*EventID=$id[\s\S]*</Suppress>") {
        throw "Unsafe query generated: critical EventID $id appears in a Suppress block."
    }
}

$queryFile = Join-Path $OutputDir "wef-querylist-noise-reduction.xml"
Set-Content -Path $queryFile -Value $queryXml -Encoding UTF8

$summary = [ordered]@{}
$summary.GeneratedAt = (Get-Date).ToString("s")
$summary.LookbackMinutes = $LookbackMinutes
$summary.CriticalSecurityEventIds = ($CriticalSecurityEventIds | Sort-Object -Unique)
$summary.SuppressedSysmonEvent1Images = $NoisyProcessImages
$summary.SuppressedSystemEventIds = @(16394)
$summary.QueryFile = $queryFile

if ($ShowBaseline) {
    $baseline = Get-SysmonEvent1Baseline -StartTime $startTime -TargetImages $NoisyProcessImages
    $summary.BaselineSysmonEvent1Counts = $baseline
}

$summaryJson = $summary | ConvertTo-Json -Depth 6
$summaryFile = Join-Path $OutputDir "noise-filter-summary.json"
Set-Content -Path $summaryFile -Value $summaryJson -Encoding UTF8

Write-Host "Generated filter artifacts:"
Write-Host " - $queryFile"
Write-Host " - $summaryFile"
Write-Host "Critical events always forwarded: $($summary.CriticalSecurityEventIds -join ', ')"