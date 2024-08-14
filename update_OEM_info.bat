@echo off
setlocal
title OEM Info Editor v0.3

:: Ensure admin privileges
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
    exit 0
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
