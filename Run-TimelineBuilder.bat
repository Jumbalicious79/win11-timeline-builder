@echo off
:: Launches timeline-builder.ps1 as Administrator with execution policy bypass
:: Users can double-click this file -- no PowerShell knowledge needed
::
:: Usage:
::   Run-TimelineBuilder.bat                     (auto-find triage zips, pick one)
::   Run-TimelineBuilder.bat "path\to\collection"
::   Run-TimelineBuilder.bat "path\to\collection.zip"
::   Run-TimelineBuilder.bat "path\to\collection" "keyword1,keyword2"
::
:: The arguments are copied into variables once and the script is started
:: with goto labels instead of parenthesized blocks, so no variable is read
:: before it is set (no delayed expansion needed; ! in paths stays intact).

setlocal
set "TB_BAT=%~f0"
set "TB_SCRIPT=%~dp0timeline-builder.ps1"
set "TB_INPUT="
set "TB_KEYWORDS="
:: Full path: the elevated copy starts in C:\Windows\System32
if not "%~1"=="" set "TB_INPUT=%~f1"
if not "%~2"=="" set "TB_KEYWORDS=%~2"

net session >nul 2>&1
if %errorlevel% equ 0 goto :run

:: Not elevated: relaunch this .bat as Administrator with the same arguments.
:: PowerShell reads the values from the environment (so spaces and ' in paths
:: need no escaping) and starts cmd.exe /s /c with the .bat path and each
:: argument in its own pair of quotes, all wrapped in one more pair of quotes.
echo Requesting Administrator privileges...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$q = [char]34; $a = '/s /c ' + $q + $q + $env:TB_BAT + $q; if ($env:TB_INPUT) { $a += ' ' + $q + $env:TB_INPUT + $q }; if ($env:TB_KEYWORDS) { $a += ' ' + $q + $env:TB_KEYWORDS + $q }; $a += $q; Start-Process -FilePath cmd.exe -ArgumentList $a -Verb RunAs"
exit /b

:run
if not defined TB_INPUT goto :browse

:: A trailing backslash would escape the closing quote for powershell.exe
:: (D:\ in quotes arrives as D: plus a quote), so double it (D:\\ arrives as D:\)
if "%TB_INPUT:~-1%"=="\" set "TB_INPUT=%TB_INPUT%\"
if not defined TB_KEYWORDS goto :direct
if "%TB_KEYWORDS:~-1%"=="\" set "TB_KEYWORDS=%TB_KEYWORDS%\"

:: Keywords are passed as one comma-separated string; the script splits it
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%TB_SCRIPT%" -InputPath "%TB_INPUT%" -Keywords "%TB_KEYWORDS%"
goto :done

:direct
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%TB_SCRIPT%" -InputPath "%TB_INPUT%"
goto :done

:browse
:: No args -- launch in browse mode to auto-find triage collections
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%TB_SCRIPT%" -Browse

:done
pause
