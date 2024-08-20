# Better Windows 11

Securing, customising and less bloated Windows Experience ! 

## Usage 🛠️

Simply Download the scripts from the Releases Page and run it as Admin.

## Future Add-ons 🚀

Full on GUI toolkit with all tweaks in One Place


## Some Gists for Windows Installations. 🗄️

#### [ei.cfg - For Selecting Windows Editions during Windows Installation.](https://gist.github.com/its-ashu-otf/9bb8a35b0a3e2532784afec1148f56b9)
Just Place it under sources folder in Windows Installer Bootable Drive.

## Custom unattended.xml for Custom Actions During Windows Installation
- Added A new unattended.xml
- Disable Automatic Driver Updates Offered by Windows
- Disable Automatic Encryption Enabled by Bitlocker.
- Ultra Debloat Before Creating User Account for a clean Experience.
- No Internet Connection Required for Windows 11 Setup.
- Many More....

  #### Usage:
  1. Create a `F:\sources\$OEM$\$$\Panther` Folder Structure Like this [ Replace `(F:)` by you're Windows 11 Installer Drive]
  2. Add the `unattended.xml` file in the Panther folder & then install Windows.
     `Tip: Add ei.cfg config file under sources folder for selecting Different Windows Versions.`

## Some More Scripts for Windows 11

[OptimumWindows](https://github.com/its-hritika/OptimumWindows)
- For Disabling Hyper-V Completely for Further Performance Boost. (Don't Use if you prefer WSL or Windows Sandbox.)

[WinUtil by @christitustech](https://github.com/ChrisTitusTech/winutil) 

```powershell
irm christitus.com/win | iex
```
