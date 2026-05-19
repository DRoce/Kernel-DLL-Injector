@echo off
setlocal EnableDelayedExpansion
title Aegis Loader

:: ==============================================================================
:: Aegis Injector - Startup Script
:: This script requests Administrator privileges, installs/starts the driver
:: service (if applicable), and launches the executable.
:: ==============================================================================

:: 1. Request Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Administrator privileges confirmed.
) else (
    echo [*] Requesting administrative privileges...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

echo ==================================================
echo             Aegis Loader
echo ==================================================
echo.

:: 2. Install and Start Driver Service
:: NOTE: aegis_loader.exe natively maps the driver itself via map_driver() 
:: in main.cpp. However, if you are migrating to a standard service-based driver 
:: (like DLL Injector 1), configure the paths below:
set "SERVICE_NAME=AegisDriver2"
set "DRIVER_PATH=%~dp0AegisDriver2\x64\Release\AegisDriver2.sys"
if not exist "%DRIVER_PATH%" set "DRIVER_PATH=%~dp0x64\Release\AegisDriver2.sys"

if exist "%DRIVER_PATH%" (
    echo [*] Driver file found. Installing and starting service...
    sc stop "%SERVICE_NAME%" >nul 2>&1
    sc delete "%SERVICE_NAME%" >nul 2>&1
    timeout /t 1 >nul
    
    echo [*] Creating driver service...
    sc create "%SERVICE_NAME%" type= kernel start= demand binPath= "%DRIVER_PATH%" DisplayName= "%SERVICE_NAME%"
    
    sc start "%SERVICE_NAME%" >nul 2>&1
    echo [+] Driver service started successfully.
) else (
    echo [*] No separate .sys driver found. Proceeding to launch executable.
    echo     ^(Note: aegis_loader maps its own driver internally^)
)
echo.

:: 3. Run the Executable
set EXE_PATH="%~dp0x64\Release\aegis_loader.exe"

if exist %EXE_PATH% (
    echo [*] Starting Aegis Loader...
    start "" %EXE_PATH%
    echo [+] Injector launched successfully.
) else (
    echo [-] ERROR: Executable not found at %EXE_PATH%.
    echo [-] Please build the aegis_loader project in Visual Studio first ^(x64 Release^).
    pause
)

:: Wait a few seconds before closing
timeout /t 3 >nul
exit /b
