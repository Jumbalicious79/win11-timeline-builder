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
:: Drag and drop: drop ONE collection .zip or folder on this file. Explorer
:: quotes a dropped path only when it has a space in it, so a path with
:: & , = ; or ^ but no space arrives cut up (this file then says the path was
:: not found): rename that folder, or run this file from a command prompt
:: with the path in quotes.
::
:: Exit code (when started from a window that is already elevated; otherwise
:: this file hands the run to a new elevated window and ends at once): the
:: builder's (0 done, 1 stopped with an error, 2 timeline incomplete), kept
:: through the pause at the end.
::
:: The arguments are copied into variables once and the script is started
:: with goto labels instead of parenthesized blocks, so no variable is read
:: before it is set (no delayed expansion needed; ! in paths stays intact).

setlocal
:: Windows PowerShell builds its default module path when PSModulePath is not
:: set. Started from PowerShell 7, cmd.exe passes PowerShell 7's path on, and
:: Windows PowerShell then loads PowerShell 7's modules (no Get-FileHash).
set "PSModulePath="
set "TB_BAT=%~f0"
set "TB_SCRIPT=%~dp0timeline-builder.ps1"
set "TB_INPUT="
set "TB_KEYWORDS="
:: Full path: the elevated copy starts in C:\Windows\System32
if not "%~1"=="" set "TB_INPUT=%~f1"
if not "%~2"=="" set "TB_KEYWORDS=%~2"

:: The input is checked here, before Administrator rights are asked for
if not defined TB_INPUT goto :checked
if not exist "%TB_INPUT%" goto :nopath
:: Two items dropped at once (two zips, a zip and its memory dump, ...): the
:: second one would be read as the keywords. A dropped path is a full path;
:: keywords are not the full path of an existing file or folder.
if not defined TB_KEYWORDS goto :checked
if not exist "%TB_KEYWORDS%" goto :checked
if /i "%~f2"=="%TB_KEYWORDS%" goto :twoitems
if /i "%~x2"==".zip" goto :twoitems
if /i "%~x2"==".dmp" goto :twoitems
if /i "%~x2"==".raw" goto :twoitems
if exist "%TB_KEYWORDS%\collection_info.json" goto :twoitems
if exist "%TB_KEYWORDS%\collection_manifest.csv" goto :twoitems
:checked

net session >nul 2>&1
if %errorlevel% equ 0 goto :run

:: Not elevated: relaunch this .bat as Administrator with the same arguments.
:: PowerShell reads the values from the environment (so spaces and ' in paths
:: need no escaping) and starts cmd.exe /s /c with the .bat path and each
:: argument in its own pair of quotes, all wrapped in one more pair of quotes.
echo Requesting Administrator privileges...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$q = [char]34; $a = '/s /c ' + $q + $q + $env:TB_BAT + $q; if ($env:TB_INPUT) { $a += ' ' + $q + $env:TB_INPUT + $q }; if ($env:TB_KEYWORDS) { $a += ' ' + $q + $env:TB_KEYWORDS + $q }; $a += $q; Start-Process -FilePath cmd.exe -ArgumentList $a -Verb RunAs"
exit /b

:nopath
echo.
echo ERROR: The collection path was not found:
echo   "%TB_INPUT%"
echo.
echo A path dropped on this file arrives cut up when it has ^& , = ; or ^^ in it
echo but no space. Rename that folder, or run this file from a command prompt
echo with the path in quotes:
echo   Run-TimelineBuilder.bat "C:\Cases\R&D\TriageCollection.zip"
echo A path of 260 or more characters is not found either: copy the collection
echo to a short path such as C:\Cases\Case1.
echo.
pause
exit /b 1

:twoitems
echo.
echo ERROR: Drop one collection at a time. More than one path was given:
echo   "%TB_INPUT%"
echo   "%TB_KEYWORDS%"
echo (The second one would have been read as the keyword list.)
echo.
pause
exit /b 1

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
:: The builder's exit code (goto keeps it; pause would reset it)
set "TB_RC=%errorlevel%"
if "%TB_RC%"=="1" echo.
if "%TB_RC%"=="1" echo Result: the builder stopped with an error (exit code 1) -- see the messages above.
if "%TB_RC%"=="2" echo.
if "%TB_RC%"=="2" echo Result: the timeline may be INCOMPLETE (exit code 2) -- see the red ERROR lines above.
pause
exit /b %TB_RC%
