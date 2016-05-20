<#
 .Synopsis
    Updates The Specified Boot Image With The Necessary Components For Refresh-MultiTool
 .DESCRIPTION
    Updates The Specified Boot Image With The Necessary Components For Refresh-MultiTool. The script will copy the final boot.wim to a new folder on the 
	the distribution point content share and rename the file to LiteTouchPE_x64.wim
	
	#Requires - The SrcBootWimPath must point to a Boot.wim which includes the SCCM binaries includes (boot.packageid.wim)

 .EXAMPLE
    .\Create-RefreshMultiToolBootWIM.ps1 -SrcBootWimPath \\svr\share\boot.CAS045B2.wim
	
 .EXAMPLE
    .\Create-RefreshMultiToolBootWIM.ps1 -SrcBootWimPath \\svr\share\boot.CAS045B2.wim -WorkingDirRoot C:\Temp\Refresh-MultiToolRefresh  -DPSrcFilePath \\svr\share\content\
 #>

Param
(
    # The filepath of a boot.wim which has SCCM binaries injected.
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [string]$SrcBootWimPath, 

    #Working Directory
    [string]$WorkingDirRoot = 'C:\Temp\Refresh-MultiToolRefresh',
    [string]$DPSrcFilePath
)

$ErrorActionPreference = 'Stop'

#Check For Admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] “Administrator”)) {
    Write-Warning “You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!”
    Break
}

#Setup The working Directory
if (! (Test-Path $WorkingDirRoot) ) {
    New-Item -Path $WorkingDirRoot -ItemType Directory
}

Copy-Item -Path $SrcBootWimPath -Destination $WorkingDirRoot\boot.RMTRefresh.wim -Force
Copy-Item -Path $SrcBootWimPath -Destination $WorkingDirRoot\boot.TSMBootStrap.wim -Force

########################################################################################
# Create The Boot.wim That Will Be Applied to C While In WinPE To Restart The TS -Child
########################################################################################
$TSMBootStrapWimMount = "$WorkingDirRoot\TSMBootStrapWimMount"
if (! (Test-Path $TSMBootStrapWimMount ) ) {
    New-Item -Path $TSMBootStrapWimMount -ItemType Directory
}

#Mount WIM
Mount-WindowsImage -ImagePath "$WorkingDirRoot\boot.TSMBootStrap.wim" -Index 1 -Path "$TSMBootStrapWimMount" 

#Update winpeshl.ini
Copy-Item "$PSScriptRoot\TSMBootStrap_winpeshl.ini" -Destination $TSMBootStrapWimMount\Windows\System32\winpeshl.ini -Force

#Commit Changes Into The Wim
Dismount-WindowsImage -Path $TSMBootStrapWimMount -Save


########################################################################################s
# Create the Boot.wim That Will Be Applied In Windows 7 To Initiate Refresh-MultiTool -Parent
########################################################################################
$RMTWimMount = "$WorkingDirRoot\RMTWimMount"
if (! (Test-Path $RMTWimMount ) ) {
    New-Item -Path $RMTWimMount -ItemType Directory
}

#Mount WIM
Mount-WindowsImage -ImagePath "$WorkingDirRoot\boot.RMTRefresh.wim" -Index 1 -Path "$RMTWimMount" 

#Copy Deployment Share Into WinPE - May Add This Back In Later
#Copy-Item "$PSScriptRoot\DS" -Destination $RMTWimMount -Recurse

#Copy In Payload
Copy-Item "$PSScriptRoot\Payload" -Destination $RMTWimMount -Recurse

#Copy In boot.TSMBootStrap.wim Into\Payload\Refresh\Boot\ As LiteTouchPE_x64.wim
Copy-Item -Path "$WorkingDirRoot\boot.TSMBootStrap.wim" -Destination "$RMTWimMount\Payload\Refresh\Boot\LiteTouchPE_x64.wim"

#Update winpeshl.ini
Copy-Item "$PSScriptRoot\RMTRefresh_winpeshl.ini" -Destination $RMTWimMount\Windows\System32\winpeshl.ini -Force

#Commit Changes Into The Wim
Dismount-WindowsImage -Path $RMTWimMount -Save

#Rename "$WorkingDirRoot\boot.RMTRefresh.wim" to LiteTouchPE_x64.wim so that it can be used inside the TS
Rename-Item -Path "$WorkingDirRoot\boot.RMTRefresh.wim" -NewName 'LiteTouchPE_x64.wim'

#Create A New SRC Folder On The DP SRC Share
$dtm = Get-Date
$PkgFolder = "Refresh-MultiTool_WinPE_Refresh_$($dtm.Month).$($dtm.Day).$($dtm.Year)"
if (! (Test-Path "$DPSrcFilePath\$PkgFolder" ) ) {
    New-Item -Path "$DPSrcFilePath\$PkgFolder" -ItemType Directory
    Copy-Item "$WorkingDirRoot\LiteTouchPE_x64.wim" -Destination "$DPSrcFilePath\$PkgFolder"
    Write-Output "Package Created At $DPSrcFilePath\$PkgFolder"
} else {
    $message  = "Destination package already exists at $DPSrcFilePath\$PkgFolder"
    $question = 'Do you want to overwrite it?'

    $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
    $decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)

    if ($decision -eq 0) {
        Copy-Item "$WorkingDirRoot\LiteTouchPE_x64.wim" -Destination "$DPSrcFilePath\$PkgFolder" -Force
        Write-Host "`r`nPackage Created At $DPSrcFilePath\$PkgFolder. `r`n Create A New Package In SCCM & Distribute Content" -ForegroundColor Green
    } else {
      break
    }
}

#Cleanup Working Directory
Remove-Item -Path $WorkingDirRoot -Recurse -Force