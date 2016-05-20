WinPE Customizations 
====================
As you may of guessed from the overview, the WinPE image that we use is customized. We started with a standard WinPE 10 (1511) SCCM boot wim, ***boot.packageid.wim***, which includes drivers and the SCCM binaries. The provided script performs the rest of the customization to the boot wim.

The resulting boot wim contains all of the scripts and tools necessary to convert the disk from MBR to GPT and change from Legacy BIOS to UEFI. In addition to this it also contains a nested boot wim which is necessary to resume the OSD Task Sequence after enabling UEFI.

##Winpeshl.ini
When WinPE loads it references a .ini file in X:\Windows\System32 called winpeshl.ini. This .ini file contains a set of commands (in the case of an OSD sequence it's only one command) that are invoked in order.

The boot wim, which is staged in phase 1, is where most of the action takes place. The winpeshl.ini contains the following commands 

```INI
[LaunchApps]
%SYSTEMDRIVE%\Windows\System32\wpeinit.exe
PowerShell.exe -ExecutionPolicy Bypass -File "%SYSTEMDRIVE%\Payload\PrepareDisk.ps1" -BootDiskType GPT -BlockFiles C:\_SMSTaskSequence\tsenv.dat
PowerShell.exe -ExecutionPolicy Bypass -File "%SYSTEMDRIVE%\Payload\Set-DellBIOSSettings\Set-DellBiosBootSettings.ps1" -BootListType uefi -FilterDeviceType "Hard Disk"
cmd /c %SYSTEMDRIVE%\Payload\Refresh\ApplyWinPEToC.bat
cmd /c %SYSTEMDRIVE%\Payload\Refresh\copyandconfigure.bat
cmd /c %SYSTEMDRIVE%\Payload\Refresh\restoretsenv.bat
```
The nested boot wim, which is staged in Phase 2, only executes two commands, as its sole purpose is to restart the task sequence. 

```INI
[LaunchApps]
%SYSTEMDRIVE%\Windows\System32\wpeinit.exe
%SYSTEMDRIVE%\sms\bin\x64\TsmBootStrap.exe /env:WinPE /configpath:C:\_SMSTaskSequence
```

## Setup Instructions
1. On your admin workstation perform the following steps:
 1. Create a Bootable USB Flash Drive using the SCCM Console
 2. Download and install the Dell Command | Configure toolkit
 3. Copy the *WinPEUSBRoot*\Boot folder to the Payload\Refresh\Boot\x64 folder
 4. Copy the *WinPEUSBRoot*\EFI folder to the Payload\Refresh\Boot\x64 folder
 5. Copy the X86_64 folder from C:\Program Files (x86)\Dell\Command Configure to *ProjectRoot*\Payload\Set-DellBiosSettings\Command_Configure
2. In Powershell execute the following as an Admin. Update the paths to your local environment.
```Powershell
.\Update-BootWIMForRefresh.ps1 -SrcBootWimPath \\svr\share\boot.packageid.wim -DPSrcFilePath \\svr\share\packages\
```
