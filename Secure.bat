@echo off
title Secure Windows
REM Check if the script is running with administrative privileges
NET SESSION >nul 2>&1
if %errorLevel% == 0 (
    goto :runScript
) else (
    echo Administrative privileges required. Restarting script with elevated privileges...
    powershell -Command "Start-Process '%0' -Verb RunAs"
    exit /B
)

:runScript
set "registryPath=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
set "valueName=ConsentPromptBehaviorAdmin"
set "newValue=1"

echo Modifying registry key: %registryPath%

reg.exe add "%registryPath%" /v "%valueName%" /t REG_DWORD /d %newValue% /f

if %errorlevel% equ 0 (
    echo Registry value "%valueName%" has been set to %newValue%.
) else (
    echo Failed to modify registry value.
)

pause
