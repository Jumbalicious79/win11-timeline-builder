@echo off
:: Launches timeline-builder.ps1 as Administrator with execution policy bypass
:: Users can double-click this file — no PowerShell knowledge needed
::
:: Usage:
::   Run-TimelineBuilder.bat                     (auto-find triage zips, pick one)
::   Run-TimelineBuilder.bat "path\to\collection"
::   Run-TimelineBuilder.bat "path\to\collection" "keyword1,keyword2"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    if "%~1"=="" (
        powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    ) else (
        powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    )
    exit /b
)

if "%~1"=="" (
    :: No args — launch in browse mode to auto-find triage collections
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0timeline-builder.ps1" -Browse
) else (
    set "PARAMS=-InputPath "%~1""
    if not "%~2"=="" set "PARAMS=%PARAMS% -Keywords %~2"
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0timeline-builder.ps1" %PARAMS%
)
pause
