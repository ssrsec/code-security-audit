@echo off
setlocal
if "%~2"=="" (
  echo Usage: %~nx0 ^<input.dll^> ^<output_dir^>
  exit /b 1
)
set "SCRIPT_DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%decompile-dotnet.ps1" -InputDll "%~1" -OutDir "%~2"
exit /b %ERRORLEVEL%
