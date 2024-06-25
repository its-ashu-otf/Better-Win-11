@echo off
REM Check if running with administrative privileges
>nul 2>&1 net session || (
    echo This script requires administrative privileges.
    pause
    exit /b
)

REM Modify registry to enable Ultimate Performance plan
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v UltimatePowerScheme /t REG_SZ /d e9a42b02-d5df-448d-aa00-03f14749eb61 /f >nul 2>&1
reg add HKLM\System\CurrentControlSet\Control\Power /v PlatformAoAcOverride /t REG_DWORD /d 0

REM Enable Ultimate Performance mode
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61


echo Please reboot your PC and now in Power Options Ultimate Performance Plan Should Be Visible.
pause

