@echo off
REM Check if running with administrative privileges
>nul 2>&1 net session || (
    echo This script requires administrative privileges.
    pause
    exit /b
)

REM Enable Ultimate Performance mode
echo Enabling Ultimate Performance mode...

REM Set power scheme to Ultimate Performance
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

REM Modify registry to enable Ultimate Performance plan
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v UltimatePowerScheme /t REG_SZ /d e9a42b02-d5df-448d-aa00-03f14749eb61 /f >nul 2>&1

REM Apply the Ultimate Performance plan
powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61

echo Ultimate Performance mode has been enabled.
pause

