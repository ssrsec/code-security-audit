@echo off
setlocal
if "%~2"=="" (
  echo Usage: %~nx0 ^<input.jar^|.class^|.war^> ^<output_dir^>
  exit /b 1
)

set "INPUT=%~1"
set "OUTDIR=%~2"
set "SCRIPT_DIR=%~dp0"
set "DECOMP_ROOT=%SCRIPT_DIR%.."

powershell -NoProfile -ExecutionPolicy Bypass -File "%DECOMP_ROOT%\lib\ensure-env.ps1" java
if errorlevel 1 exit /b 1

set "CFR_JAR=%DECOMP_ROOT%\java\cfr-0.152.jar"
if not exist "%CFR_JAR%" (
  echo ERROR: CFR not found at %CFR_JAR%
  exit /b 1
)
if not exist "%INPUT%" (
  echo ERROR: input not found: %INPUT%
  exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"
java -jar "%CFR_JAR%" "%INPUT%" --outputdir "%OUTDIR%" --silent true
if errorlevel 1 exit /b 1
echo Decompiled to: %OUTDIR%
