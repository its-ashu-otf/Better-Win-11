@echo off
setlocal
title Update OEM information

REM Check if the script is run as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: This script must be run with administrative privileges.
    echo Please run this script as an administrator and try again.
    pause
    exit /b 1
)

echo OEM Info Editor By @its_ashu_otf

REM Prompt the user to input company information
set /p companyName="Enter company name: "
set /p companyWebsite="Enter company website: "
set /p supportContact="Enter support contact information: "
set /p supportHours="Enter support hours: "
set /p deviceModel="Enter the device model: "

REM Set the OEM information in the registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /d "%companyName%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /d "%companyWebsite%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /d "%supportContact%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /d "%supportHours%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /d "%deviceModel%" /f

echo OEM information has been updated successfully.

endlocal
