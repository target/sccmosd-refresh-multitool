Refresh Multi-Tool
====================

A self-contained method for SCCM OSD Task Sequences to migrate a Windows 7 x64 computer to Windows 10 x64 in place while handling the following:
* The device may or may not be encrypted with a 3rd party disk encryption software that cannot be easily disabled. 
* After the procces is executed the local disk will be structured with GPT partitions
* After the process is executed the BIOS will be configured to UEFI
* Executed as part of a single task sequence
* Executes on Dell OptiPlex, Latitude and Precision line hardware

I want to recognize my team for their contributions to this effort; without them none of this would be possible. In no particular order they are Bob Burnes, Eric Michaelson and Kent Vareberg. Thanks Guys! You Rock!!

Back when we were migrating from Windows XP to Windows 7 there were very few options to Refresh a PC if you had third party encryption software installed. Short of high-touch vendor options, decrypting every PC or standing up PXE infrastructure across your enterprise most customers like us where out of luck. My organization has ~70K endpoints spread out across the globe and the idea of sending an technican out to each and every computer was nothing short of a nightmare. We needed a automated technician-free method of migrating a user to Windows 7.

Why is this guy talking about migrating users from Windows XP to Windows 7? Easy, the method we developed for that is what this solution is based on. 

Before I go further I need to take care of some house keeping items.  
* We haven't tested this process on all Dell hardware models so your experience may differ depending on their support of CCTK.
* This process will completely erase the hard disk of the computer and, once started, there is no going back. You've been warned. 

## Overview
The diagram below illustrates at a high-level the steps which are executed as part of the Refresh Multi-Tool. 
* ***Phase 1*** is executed inside the full OS (Windows 7) right after USMT captures the user state to a network share. The goal of this phase is to stage WinPE on the local disk and persist the TSEnv.dat file which is used by the task sequence. 
* ***Phase 2*** is executed from within the WinPE Ramdisk. The goal of this phase is to wipe the disk and reformat with GPT disks, convert the BIOS to UEFI, stage WinPE back on the local disk and with the files necessary to continue the build. 
 * We chose to make this step self-sufficient and not reach out to network shares or web servers for content. While it can be updated to reach out for content we did not feel that the benefit outweighed the risk to an already complex process.  
* ***Phase 3*** is executed from the context of the WinPE Ramdisk that got staged to the local disk in Phase 2.  The goal of this phase is to restart the task sequence where it left off previously. 

![Alt text](/Images/overview.png)

## License & Authors
Authors: 
* Mike Beckel (Mike.Beckel@target.com)
* Kent Vareberg
* Eric Michaelson
* Bob Burnes

```text
Copyright: 2016, Target Corporation

See License for details
```