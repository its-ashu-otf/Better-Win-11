@echo off
setlocal
title Update OEM Information

REM Check if the script is run as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Administrative privileges are required to run this script.
    echo Please restart this script as an administrator.
    pause
    exit /b 1
)

echo Welcome to the OEM Info Editor by @its_ashu_otf

REM Prompt the user to input company information
echo Please enter the following OEM details:
set /p companyName="Company Name: "
set /p companyWebsite="Company Website: "
set /p supportContact="Support Contact Information: "
set /p supportHours="Support Hours: "
set /p deviceModel="Device Model: "

REM Update the OEM information in the registry
echo Updating OEM information in the registry...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /d "%companyName%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /d "%companyWebsite%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /d "%supportContact%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /d "%supportHours%" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /d "%deviceModel%" /f

echo OEM information has been successfully updated.

endlocal
