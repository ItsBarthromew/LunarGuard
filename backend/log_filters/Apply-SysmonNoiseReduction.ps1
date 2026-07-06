param(
    [Parameter(Mandatory = $true)]
    [string]$SysmonExePath,

    [string]$ConfigPath = ".\sysmon-noise-reduction.xml"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path $SysmonExePath)) {
    throw "Sysmon executable not found at: $SysmonExePath"
}

if (-not (Test-Path -Path $ConfigPath)) {
    throw "Config file not found at: $ConfigPath"
}

Write-Host "Applying Sysmon config: $ConfigPath"
& $SysmonExePath -c $ConfigPath

if ($LASTEXITCODE -ne 0) {
    throw "Sysmon config apply failed with exit code: $LASTEXITCODE"
}

Write-Host "Sysmon noise-reduction config applied successfully."
