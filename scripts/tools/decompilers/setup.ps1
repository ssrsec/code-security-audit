# 显式初始化：检测环境并安装全部反编译依赖
param()
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& (Join-Path $ScriptDir "lib\ensure-env.ps1") -Mode all
