# 检测运行环境并按需自动安装反编译依赖
param(
    [string]$Mode = "all",
    [switch]$LoadOnly  # 仅加载函数（供 decompile-*.ps1 点源引用）
)

$ErrorActionPreference = "Stop"
$DecompRoot = Split-Path -Parent $PSScriptRoot
$DotnetToolPath = Join-Path $DecompRoot "dotnet"
$IlspyVersion = "9.1.0.7988"
$AutoInstall = if ($null -ne $env:DECOMPILERS_AUTO_INSTALL) { $env:DECOMPILERS_AUTO_INSTALL } else { "1" }

function Log($msg) { Write-Host "[decompilers] $msg" -ForegroundColor Cyan }

function Test-IlspyWorks($bin) {
    if (-not (Test-Path $bin)) { return $false }
    try { & $bin --help 2>&1 | Out-Null; return $LASTEXITCODE -eq 0 } catch { return $false }
}

function Install-Java {
    Log "未检测到 java，尝试自动安装 Temurin JRE..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install -e --id EclipseAdoptium.Temurin.17.JRE `
            --accept-package-agreements --accept-source-agreements | Out-Null
        return $true
    }
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install temurin17jre -y | Out-Null
        return $true
    }
    return $false
}

function Ensure-Java {
    if (Get-Command java -ErrorAction SilentlyContinue) { return }
    if ($AutoInstall -ne "1") {
        throw "未找到 java。请安装 JRE 8+，或设置环境变量 DECOMPILERS_AUTO_INSTALL=1"
    }
    if (-not (Install-Java)) {
        throw "无法自动安装 Java。请从 https://adoptium.net/ 安装 JRE 8+"
    }
    if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
        throw "Java 安装后仍未在 PATH 中，请重启终端后重试"
    }
}

function Install-DotNetSdk {
    Log "未检测到 dotnet，尝试自动安装 .NET SDK 8..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install -e --id Microsoft.DotNet.SDK.8 `
            --accept-package-agreements --accept-source-agreements | Out-Null
        return $true
    }
    return $false
}

function Install-IlspyCmd {
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        if ($AutoInstall -eq "1") { [void](Install-DotNetSdk) }
    }
    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        throw "未找到 dotnet。请安装 .NET SDK 8+：https://dotnet.microsoft.com/download"
    }
    New-Item -ItemType Directory -Force -Path $DotnetToolPath | Out-Null
    Log "安装/更新 ilspycmd $IlspyVersion ..."
    $installed = $false
    try {
        dotnet tool install ilspycmd --version $IlspyVersion --tool-path $DotnetToolPath 2>$null
        $installed = $true
    } catch { }
    if (-not $installed) {
        dotnet tool update ilspycmd --version $IlspyVersion --tool-path $DotnetToolPath
    }
}

function Resolve-IlspyCmd {
    $bundled = Join-Path $DotnetToolPath "ilspycmd.exe"
    if (Test-IlspyWorks $bundled) { return $bundled }
    if ((Test-Path $bundled) -and -not (Test-IlspyWorks $bundled)) {
        Log "内置 ilspycmd 与当前平台不匹配，将重新安装..."
        Remove-Item -Force $bundled -ErrorAction SilentlyContinue
    }
    if ($AutoInstall -eq "1") {
        Install-IlspyCmd
        if (Test-IlspyWorks $bundled) { return $bundled }
    }
    if (Get-Command ilspycmd -ErrorAction SilentlyContinue) {
        $p = (Get-Command ilspycmd).Source
        if (Test-IlspyWorks $p) { return $p }
    }
    throw "ilspycmd 不可用"
}

function Ensure-DotNet {
    [void](Resolve-IlspyCmd)
}

if (-not $LoadOnly) {
    switch ($Mode) {
        "java"   { Ensure-Java }
        "dotnet" { Ensure-DotNet }
        "all"    { Ensure-Java; Ensure-DotNet }
        default  { throw "Usage: ensure-env.ps1 [java|dotnet|all]" }
    }
}
