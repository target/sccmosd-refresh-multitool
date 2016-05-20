REM Based On https://blogs.msdn.microsoft.com/steverac/2013/09/13/osd-pre-stage-and-uefi-systems/

xcopy %SYSTEMDRIVE%\Payload\Refresh\Boot\x64\EFI\* S:\EFI\* /cherkyfs 
xcopy %SYSTEMDRIVE%\Payload\Refresh\Boot\LiteTouchPE_x64.wim C:\sources\* /cherkyfs
rename C:\sources\LiteTouchPE_x64.wim boot.wim

copy %SYSTEMDRIVE%\Payload\Refresh\Boot\x64\boot\boot.sdi C:\sources\ 
copy %SYSTEMDRIVE%\Payload\Refresh\Boot\x64\efi\microsoft\boot\*.efi s:\efi\Microsoft\boot\* 
copy %SYSTEMDRIVE%\Payload\Refresh\Boot\x64\efi\boot\*.efi s:\efi\Microsoft\boot\* 
copy %SYSTEMDRIVE%\Windows\boot\EFI\*.efi S:\EFI\Microsoft\Boot\*

del S:\EFI\Microsoft\Boot\BCD /f

bcdedit -createstore S:\EFI\Microsoft\Boot\BCD 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -create {bootmgr} /d "Boot Manager" 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -create {globalsettings} /d "globalsettings"
bcdedit -store S:\EFI\Microsoft\Boot\BCD -create {dbgsettings} /d "debugsettings"
bcdedit -store S:\EFI\Microsoft\Boot\BCD -create {ramdiskoptions} /d "ramdiskoptions"

For /f "Tokens=1,2,3" %%a in ('bcdedit -store S:\EFI\Microsoft\Boot\BCD -create /d "Windows PE" /application osloader') Do Set PreStagePEID=%%c

bcdedit -store S:\EFI\Microsoft\Boot\BCD /default %PreStagePEID%

bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {bootmgr} device partition=s: 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {bootmgr} path \EFI\Microsoft\Boot\bootmgfw.efi 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {bootmgr} locale en-us 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {bootmgr} timeout 10

bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {Default} device ramdisk=[C:]\sources\boot.wim,{ramdiskoptions} 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {Default} path \windows\system32\winload.efi 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {Default} osdevice ramdisk=[C:]\sources\boot.wim,{ramdiskoptions} 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {Default} systemroot \windows 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {Default} winpe yes 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {Default} nx optin 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {Default} detecthal yes 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -displayorder {Default} -addfirst

bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {dbgsettings} debugtype Serial 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {dbgsettings} debugport 1 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {dbgsettings} baudrate 115200

bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {ramdiskoptions} ramdisksdidevice partition=C: 
bcdedit -store S:\EFI\Microsoft\Boot\BCD -set {ramdiskoptions} ramdisksdipath \sources\boot.sdi