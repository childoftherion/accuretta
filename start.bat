@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title accuretta

echo.
echo ============================================================
echo   accuretta - local llama.cpp bridge + IDE
echo ============================================================
echo.

REM ---- kill anything holding port 8787 -------------------------
echo freeing port 8787 ...
for /f "tokens=5" %%p in ('netstat -ano 2^>nul ^| findstr ":8787" ^| findstr "LISTENING"') do (
    echo   killing pid %%p
    taskkill /F /PID %%p >nul 2>&1
)

REM ---- kill any stale bridge.py python/pythonw processes -------
echo killing stale bridge.py processes ...
for /f "skip=1 tokens=1 delims=," %%p in ('wmic process where "CommandLine like '%%bridge.py%%' and not CommandLine like '%%wmic%%'" get ProcessId /format:csv 2^>nul') do (
    if not "%%p"=="" if not "%%p"=="Node" (
        taskkill /F /PID %%p >nul 2>&1
    )
)

REM ---- find python ---------------------------------------------
set "PYEXE="
where py >nul 2>&1
if not errorlevel 1 set "PYEXE=py -3"
if not defined PYEXE (
    where python >nul 2>&1
    if not errorlevel 1 set "PYEXE=python"
)
if not defined PYEXE (
    echo [error] python not found on PATH. install Python 3.10+ from python.org.
    pause
    exit /b 1
)
echo python: %PYEXE%
echo.

echo network addresses (use one of these from your phone):
ipconfig | findstr /c:"IPv4"
echo.
echo the bridge will spawn llama-server itself with the model you pick in
echo Settings -^> Models folder. browser opens automatically once ready.
echo ctrl+c to stop.
echo.

REM ---- pick which browser to launch ----------------------------
REM   uncomment ONE of the lines below to override your system default.
REM   set values: chrome | firefox | edge | brave | opera | vivaldi | none
REM
REM set ACCURETTA_BROWSER=chrome
REM set ACCURETTA_BROWSER=firefox
set ACCURETTA_BROWSER=edge
REM set ACCURETTA_BROWSER=brave
REM set ACCURETTA_BROWSER=none
REM
REM Or pass it as the first argument: start.bat firefox
if not "%~1"=="" set "ACCURETTA_BROWSER=%~1"
if defined ACCURETTA_BROWSER echo browser override: %ACCURETTA_BROWSER%
echo.

REM bridge spawns llama-server, binds 8787, opens browser, then serves.
%PYEXE% -u bridge.py

echo.
echo bridge stopped.
pause
exit /b 0
