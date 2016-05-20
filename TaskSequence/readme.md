Task Sequence Updates
====================

The screenshot below is a snippit of our Windows 10 Task Sequence. The **Refresh** Only section is separated into two sections, because our Windows 10-to-Windows 10 refresh requires no extra customizations.

![Task Sequence Snippit](../Images/tasksequence_steps.png)

###Copy WinPE to Deployroot
Refresh Multi-Tool is designed to be used with an MDT integrated OSD Task Sequence; however, instead of including the LitetouchPE_x64.wim inside the Deployment Toolkit package and downloading it unnecessarily when it's not needed, we chose to deliver it just in time by copying it from the package to the %deployroot%\boot folder during execution. The wim is almost 1GB in size so this approach will result in some measurable time savings.  

![copywinpetodeployroot_properties](../Images/copywinpetodeployroot_properties.png)
```DOS
cmd.exe /c xcopy *.* %DeployRoot%\Boot /h/k/i/s/e/r/y
```

###Apply WinPE
Now that we have WinPE in %DeployRoot%\Boot, the next step is to use an updated version of LTIApply.wsf to configure the device to boot into WinPE at the next reboot.

>The built-in *Restart Computer* task sequence step should **not** be used. It does something similar to the RMT_LTIApply.wsf script  when you choose the *The boot image assigned to this task sequence* option; however, executing this step where the hard disk encypted with a non-BitLocker solution will render it unbootable. This is because the built-in step runs *bootsect.exe /nt60 c: /mbr* which wipes out the MBR and results in an unbootable encrypted disk.

RMT_LTIApply.wsf is based on LTIApply.wsf which is included with the MDT Deployment Toolkit. The only modification to the file is the removal of the **/mbr** parameter on the bootsect.exe command. **You are responsible for making this update in your Deployment Toolkit package.**

![applywinpe_properties](../Images/applywinpe_properties.png)
```DOS
cscript %DeployRoot%\Scripts\RMT_LTIApply.wsf /pe
```

### Update WinPE
In this step the wim that is located in C:\sources\boot.wim is mounted so that it can be further customized. The only runtime customization is copying the C:\\_SMSTaskSequence\\TSEnv.dat to the mounted boot wim.

>The TSEnv.dat file maintains the Task Sequence policy and the progress of the Task Sequence. Since the local disk is encrypted and unreadable from within WinPE, the TSEnv.dat file must be copied into WinPE so it's available later. 

Note: Additional files that need to be persisted can be copied in, if needed, at this time.

![updatewinpe_properties](../Images/updatewinpe_properties.png)
```DOS
cscript %DeployRoot%\Scripts\RMT_RefreshPC.wsf
```
![updatewinpe_options](../Images/updatewinpe_options.png)

It's important that you add a condition to this step **_SMSTSInWinPE = False** so that the step doesn't try to execute again once the Task Sequence is resumed. This is because the TSEnv.dat was previously copied into the boot wim so it won't know that this step has already been executed.  

### Restart Computer
Next the computer needs to be restarted so that it can boot into WinPE and start the conversion process. Since WinPE has already been staged, and the boot loader is configured to boot into WinPE, select **The currently installed default operating system**.

![restartcomputer_properties](../Images/restartcomputer_properties.png)

![restartcomputer_options](../Images/restartcomputer_options.png)

It's important that you add a condition to this step **_SMSTSInWinPE = False** so that the step doesn't try to execute again once the Task Sequence is resumed later.

### WinPE Actions
The rest of the Refresh MultiTool process occurs outside of the Task Sequence while still in WinPE. The readme.md file in the WinPE folder provides more details.

### Create DiskPart Script
The build has now entered Phase 3 of the process, and the Task Sequence has been resumed, now that the system has booted using UEFI and a GPT disk.
> During development of this solution it was identified that BCD file in the EFI partition was not updated correctly so the build failed during OOBE. Instead of just deleting the BCD file, the entire EFI partition is formatted so that it's clean of artifacts and OSD can update it natively.

This step will eventually be cleaned up so we're not creating the file live, but it works for now. 

![creatediskpartscript__properties](../Images/creatediskpartscript__properties.png)
```DOS
cmd /c echo Select Disk 0 >> %SYSTEMROOT%\Temp\WipeS.txt && echo Select Volume 1 >> %SYSTEMROOT%\Temp\WipeS.txt && echo format fs=fat32 quick Label=SYSTEM >> %SYSTEMROOT%\Temp\WipeS.txt
```

### Execute DiskPart Script
Run DiskPart.exe and reference the file created in the previous step to format the EFI partition.
 
![executediskpartscirpt_properties](../Images/executediskpartscirpt_properties.png)
```DOS
diskpart.exe /s %SYSTEMROOT%\Temp\WipeS.txt
```

### Use Toolkit Package
Stage the Deployment Toolkit package.
![usetoolkitpackage_properties](../Images/usetoolkitpackage_properties.png)

### Gather
Execute Gather to acknowledge the updates made to the system. 
![gather_properties](../Images/gather_properties.png)