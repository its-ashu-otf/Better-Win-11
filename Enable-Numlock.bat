@echo off
setlocal EnableDelayedExpansion

:: ===================================================
:: Script Title: NumLock Enabler
:: Author: its-ashu-otf
:: ===================================================

:: === Elevation Check ===
>nul 2>&1 net session
if %errorlevel% neq 0 (
    echo [!] Admin rights required. Attempting to relaunch with elevation...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

:: === UI Start ===
echo ===================================================
echo         NumLock Enabler - by its-ashu-otf
echo ===================================================

echo.
echo Choose your system type:
echo.
echo  [1] OEM Laptop / Gaming System (e.g. ROG, Dell, HP, Lenovo)
echo  [2] Standard PC / Desktop / Custom Build
echo.

set /p choice="Enter your choice (1 or 2): "

if "%choice%"=="1" (
    set KEYBOARD_VALUE=2147483650
    echo You selected: OEM Laptop/Gaming System
) else if "%choice%"=="2" (
    set KEYBOARD_VALUE=2
    echo You selected: Standard PC/Desktop
) else (
    echo [ERROR] Invalid choice. Exiting.
    pause
    exit /b
)

:: === Apply Registry Setting ===
echo.
echo Setting registry value: !KEYBOARD_VALUE!

reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d !KEYBOARD_VALUE! /f

if !errorlevel! == 0 (
    echo [SUCCESS] Registry updated successfully.
) else (
    echo [ERROR] Failed to update registry. Please ensure you ran this as Administrator.
)

echo.
echo Reboot your system for the changes to take effect.
pause
