param(
    [Parameter(Mandatory = $true)][string]$InputDll,
    [Parameter(Mandatory = $true)][string]$OutDir
)
$BinDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DecompRoot = Split-Path -Parent $BinDir
. (Join-Path $DecompRoot "lib\ensure-env.ps1") -LoadOnly
$ilspy = Resolve-IlspyCmd
if (-not (Test-Path $InputDll)) { throw "input not found: $InputDll" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& $ilspy $InputDll -p -o $OutDir
Write-Host "Decompiled to: $OutDir"
