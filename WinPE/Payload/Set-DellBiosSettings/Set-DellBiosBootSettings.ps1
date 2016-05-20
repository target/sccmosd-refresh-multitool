# Filename:      Set-DellBiosBootSettings.ps1
# Version:       1.0
# Description:   Sets the BIOS type and boot settings for supported Dell computers
# Author:        Kent Vareberg, Desktop and Hardware Engineering


<#
.Synopsis
    Sets the BIOS type and boot settings for supported Dell computers.


.Description
    Sets the BIOS type and boot settings for supported Dell computers.

    See the PARAMETERS and NOTES sections for more information.


.Parameter BootListType
    Default is "uefi".  Options are "uefi" or "legacy".

.Parameter DisableMatchingDevices
    Default is to enable matching devices.  This parameter will disable devices that match the filters.

.Parameter FilterDeviceDescription
    Default is null.  Use a RegEx to match device description (e.g. "Windows Boot Manager") as a filter to define priority order for boot devices.

.Parameter FilterDeviceNumber
    Default is null.  Use a RegEx to match device number (e.g. 0, 1, 18) as a filter to define priority order for boot devices.

.Parameter FilterDeviceStatus
    Default is null.  Use a RegEx to match device status (e.g. "Enabled" or "Disabled") as a filter to define priority order for boot devices.

.Parameter FilterDeviceType
    Default is null.  Use a RegEx to match device type (e.g. "Hard Disk") as a filter to define priority order for boot devices.

.Parameter FilterShortform
    Default is null.  Use a RegEx to match device shortform (e.g. "hdd", "hdd.1") as a filter to define priority order for boot devices.

.Parameter IncludeAllRemainingBootDevices
    Default is to only include boot devices that match filters.  This parameter will include and enable/disable all boot devices not matched by the filters.

.Parameter LogFile
    Default is %SystemDrive%\Windows\Temp\<ScriptBaseName>.log

.Parameter MaxLogSizeBytes
    Default is 5 MB; specify 0 to let grow indefinitely.

.Parameter SkipHapiPreinstall
    Default is to pre-install HAPI at beginning of the script.  This parameter skips HAPI pre-installation, if it's known to already be installed, to reduce script execution time.

.Parameter SkipHapiRemoval
    Default is to remove HAPI at end of the script.  This parameter skips HAPI removal and leaves it installed, if it's known that the script will be executed again.

.Parameter SortFilterMatchesDescending
    Default is to sort filter-matching devices only based on device number in ascending order (0, 1, 2).  This parameter sorts only filter-matching devices based on device number in descending order (2, 1, 0).


.Example
    This example sets the boot type to LEGACY and orders all boot devices based on CCTK DeviceNumber:

    Set-DellBiosBootSettings.ps1 -BootListType LEGACY


.Example
    This example sets the boot type to UEFI, orders hard disks first, and further orders "Windows Boot Manager" before remaining hard disks:

    Set-DellBiosBootSettings.ps1 -BootListType uefi -FilterDeviceType "Hard Disk" -FilterDeviceDescription "Windows Boot Manager"


.Example
    This example uses the script 4 times, executed in "reverse order," to effectively set the boot order to IPv4 PXE, then "Windows Boot Manager," then remaining local hard disks, and disable all other boot devices:

    #1 sets the boot type to UEFI, disables and orders all devices based on CCTK DeviceNumber, and keeps HAPI installed when finished:

        Set-DellBiosBootSettings.ps1 -BootListType uefi -DisableMatchingDevices -SkipHapiRemoval


    #2 sets the boot type to UEFI, enables and orders hard disks to be first, skips the HAPI pre-install (still loaded from previous script), and keeps HAPI installed when finished:

        Set-DellBiosBootSettings.ps1 -BootListType uefi -FilterDeviceType "Hard Disk" -SkipHapiPreinstall -SkipHapiRemoval


    #3 sets the boot type to UEFI, enables and orders "Windows Boot Manager" to be first (before other hard disks), skips the HAPI pre-install (still loaded from previous script), and keeps HAPI installed when finished:

        Set-DellBiosBootSettings.ps1 -BootListType uefi -FilterDeviceDescription "Windows Boot Manager" -SkipHapiPreinstall -SkipHapiRemoval


    #4 sets the boot type to UEFI, enables and orders "Onboard NIC(IPV4)" (IPv4 PXE) to be first (note: backslashes required to escape parentheses), skips the HAPI pre-install (still loaded from previous script), and removes HAPI when finished:

        Set-DellBiosBootSettings.ps1 -BootListType uefi -FilterDeviceDescription "Onboard NIC\(IPV4\)" -SkipHapiPreinstall


.Notes
    -This script must be executed from an elevated PowerShell process.

    -The Logging.psm1 module must be in the same folder as this script to generate a CMTrace-compatible log file.
    
    -HAPI (Hardware API) is required.  If not pre-installed, HAPI will be auto-installed and removed for each CCTK execution, which slows down the script. 
    
    -Boot devices that match filters will be moved to the top of the list and ordered based on CCTK DeviceNumber in ascending order or descending order, if -SortFilterMatchesDescending specified.

    -Boot devices that don't match filters will remain in their respective order AFTER the boot devices that match the filters.
    
    -Boot devices that match filters or from IncludeAllRemainingBootDevices will be set to Enabled or Disabled, if -DisableMatchingDevices specified.

    -Run the script multiple times starting with the most generic filter and then more precise filters to make specific devices move to top of list.
    
    -After the boot devices found using a filter are set, the Dell CCTK will keep all remaining boot devices in their respective state and order, so it's not required to specify every device using a filter.
    
    -The return code will be:
        0: Success - zero warnings and zero errors were encountered and all settings set successfully
        1: Warning - one or more warnings and zero errors were encountered
        2: Error   - one or more errors were encountered
#>


##################################
### Get the default parameters ###
##################################
Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("legacy","uefi")] 
    [string]$BootListType ="uefi",

    [switch]$DisableMatchingDevices,

    [Parameter(Mandatory=$False)]
    [string]$FilterDeviceDescription = "",

    [Parameter(Mandatory=$False)]
    [string]$FilterDeviceNumber = "",

    [Parameter(Mandatory=$False)]
    [string]$FilterDeviceStatus = "",

    [Parameter(Mandatory=$False)]
    [string]$FilterDeviceType = "",

    [Parameter(Mandatory=$False)]
    [string]$FilterShortform = "",

    [switch]$IncludeAllRemainingBootDevices,

    [Parameter(Mandatory=$false)]
    [string]$LogFile = "<Default>",

    [Parameter(Mandatory=$false)]
    [int]$MaxLogSizeBytes=(5 * 1024 * 1024),

    [switch]$SkipHapiPreinstall,

    [switch]$SkipHapiRemoval,

    [switch]$SortFilterMatchesDescending
)


#################################################
### Check if running with elevated privileges ###
#################################################
function IsAdmin
{
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()  
    $principal = new-object System.Security.Principal.WindowsPrincipal($identity)  
    $admin = [System.Security.Principal.WindowsBuiltInRole]::Administrator  
    
    return $principal.IsInRole($admin)  
}


######################################################################
### Function to test a path/file including hidden and system files ###
######################################################################
function Test-PathEx
{
    param($Path)

    if (Test-Path $Path)
    {
        $true
    }
    else
    {
        $parent = Split-Path $Path
        [System.IO.Directory]::EnumerateFiles($Parent) -contains $Path
    }
}


###################################################
### Function to test a path and suppress errors ###
###################################################
Function TestPathQuiet
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$DirOrFile = "<Default Dir or File>"
    )

    if ($DirOrFile -ieq "<Default Dir or File>" -or $DirOrFile -eq "")
    {
        # Nothing specified, return empty string
        return $false
    }

    $bTestPathRslt = $null
    try { $bTestPathRslt = test-pathex $DirOrFile -ErrorAction Stop }
    catch { $bTestPathRslt = $false }

    return $bTestPathRslt
}


######################################################################
### Function to remove quote if string starts AND ends with quotes ###
######################################################################
Function TrimQuotes
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$String = ""
    )

    $strFuncRslt = $String     # Set default function result to input string

    # Make sure string is at least 2 characters long (to have a starting and ending quote)
    if ($String.Length -ge 2)
    {
        # If first and last characters are double quotes
        if ($String.IndexOf("`"") -eq 0 -and $String.LastIndexOf("`"") -eq $String.Length -1)
        {
            # Set the function result to exclude the first and last character (the double quotes)
            $strFuncRslt = $String.Substring(1, $String.Length -2) 
        }
    }

    return $strFuncRslt
}


############################################################################
### Function to remove the beginning of a text file until the next block ###
############################################################################
Function TrimTextFileBlock
{
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$LogFile,

        [Parameter(Mandatory=$true,Position=2)]
        [int]$MaxSizeBytes,

        [Parameter(Mandatory=$false,Position=3)]
        [string]$Header="",

        # Trims at the line that exceeds the filesize limit instead of the next "block"
        [switch]$TrimOnOverageLine,

        # Trims at the line that exceeds the filesize limit if no next "block" is found
        [switch]$TrimOnOverageLineIfNoBlockFound,

        # Switch to ensure the header is retained at the top
        [switch]$PreserveHeader
    )

    # Make sure the file exists
    if ((TestPathQuiet -DirOrFile $Logfile) -eq $false)
    {
        return "File not found"         # File not found, nothing to do
    }

    # Make sure the file size exceeds the max size
    $iLogFileSize = gci $LogFile | select -ExpandProperty Length

    if ($iLogFileSize -le $MaxSizeBytes -or $iLogFileSize -eq 0)
    {
        return "File size is zero or less than maximum size"
    }
    
    # Determine if content ends with a newline (`n)
    $iBytesFoundInReverse = 0      # Cumulative bytes per line
    $iLineExceedsLimit = 0         # Set the line that goes over the file size limit

    # If PreserveHeader specified, also add length of header plus 2 (for newline)
    if ($PreserveHeader -eq $true)
    {
        $iBytesFoundInReverse += $Header.Length +2
    }
            
    # Requires PowerShell 3.0 or higher
    if ($host.Version -ge "3.0")
    {
        # Get the last raw line of the file as a string to determine if it ends with a newline (`n)
        # Without -raw it doesn't account for newline as last char
        $strLogContent = get-content -Path $LogFile -Encoding ascii -Raw

        if ($strLogContent.LastIndexOf("`n") -eq ($strLogContent.Length -1))
        {
            $iBytesFoundInReverse += 2
        }

        # Free up the memory
        Remove-Variable strLogContent -Force
    }

    # Read the entire file again without -raw (as an array)
    $arrLogContent = @(get-content -Path $LogFile -Encoding ascii)

    # Start at the end and work backwards to determine what line contains the max file size
    for ($i = ($arrLogContent.Count -1); $i -ge 0; $i--)
    {
        # Add length to cumulative byte count
        $iBytesFoundInReverse += $arrLogContent[$i].length
        
        # Also add 2 for newlines if not on the last line
        if ($i -lt ($arrLogContent.Count -1))
        {
            $iBytesFoundInReverse += 2
        }

        # If the max bytes is exceeded then set the starting line for searching forward
        if ($iBytesFoundInReverse -gt $MaxSizeBytes)
        {
            $iLineExceedsLimit = $i
            break
        }
    }
    
    # Check if trimming at line causing overage or the next block
    if ($TrimOnOverageLine -eq $true)
    {
        # Trim using the line that caused the overage
        $iNextBlockLine = $iLineExceedsLimit +1
    }
    else
    {
        # Find the next "block" (first non-blank line after the first blank line after the line with the overage)
        $iFirstBlankLine = 0
        $iNextBlockLine = 0

        for ($i = $iLineExceedsLimit; $i -lt $arrLogContent.Count; $i++)
        {
            # Get the first blank line
            if ($arrLogContent[$i].length -eq 0 -and $iFirstBlankLine -eq 0)
            {
                # Found a blank line
                $iFirstBlankLine = $i
            }

            # Get the first non-blank line
            if ($arrLogContent[$i].length -gt 0 -and $iFirstBlankLine -gt 0 -and $iNextBlockLine -eq 0)
            {
                # Found a blank line
                $iNextBlockLine = $i
            }

            # Exit for loop if both numbers > 0
            if ($iFirstBlankLine -gt 0 -and $iNextBlockLine -gt 0) { break }
        }

        # If the next block line isn't found and the TrimOnOverageLineIfNoBlockFound switch is enabled
        if ($iNextBlockLine -eq 0 -and $TrimOnOverageLineIfNoBlockFound -eq $true)
        {
            # Trim using the line that caused the overage
            $iNextBlockLine = $iLineExceedsLimit +1
        }
    }
        
    # Check if lines to skip wasn't determined (still at 0)
    if ($iNextBlockLine -eq 0)
    {
        return "Unable to determine trim point, no file changes made"
    }    

    # Create new array with file content by skipping the beginning lines to get below the max filesize threshold
    $arrLogContentModified = $arrLogContent | select -Skip $iNextBlockLine
    if ($arrLogContentModified -eq $null) { $arrLogContentModified = @() }

    # If preserving the header, and the first line doesn't match the header, prepend it to the array
    if (($arrLogContentModified[0] -ine $strHeader) -and ($PreserveHeader -eq $true) -and ($Header -ne ""))
    {
        $arrLogContentModified = @($Header) + $arrLogContentModified
    }

    # Try overwriting the file contents
    $bFileUpdated = $true                                                      # Flag indicating success
    try{ out-file -FilePath $LogFile -InputObject $arrLogContentModified -encoding ascii }

    catch [System.UnauthorizedAccessException]
    {
        #write-host "`nERROR: Access denied for log file" -ForegroundColor Red
        $bFileUpdated = $False
    }

    catch [System.IO.IOException]
    {
        
        $bFileUpdated = $False
    }
    
    # Show if line not written to log
    if ($bFileUpdated -eq $false -and $DisplayInHost -eq $true)
    {
        #write-host "ERROR: Unable to update the log file, make sure it's not open in another application`n" -ForegroundColor Red
    }
    
    # Free up memory
    Remove-Variable arrLogContent -Force
    Remove-Variable arrLogContentModified -Force

    # Return function result
    if ($bFileUpdated -eq $true)
    {
        return "File trim succeeded"
    }
    else
    {
        return "File trim failed"
    }
}


##################################################################################
### Function to execute a process and return stdout, stderr, and the exit code ###
##################################################################################
Function Execute-Command
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$commandPath = $null,    # Requires full path, relative path not allowed

        [Parameter(Mandatory=$False,Position=2)]
        [string[]]$commandArguments = @(),

        [Parameter(Mandatory=$False,Position=3)]
        [string]$commandTitle = ""
    )

    if ((TestPathQuiet -DirOrFile $commandPath) -eq $true)
    {
        # File found
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $commandPath
        $pinfo.RedirectStandardError = $true
        $pinfo.RedirectStandardOutput = $true
        $pinfo.UseShellExecute = $false
        $pinfo.Arguments = $commandArguments
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $pinfo
        $p.Start() | Out-Null
        $p.WaitForExit()
    
        return [pscustomobject]@{
            commandTitle = $commandTitle
            stdout = $p.StandardOutput.ReadToEnd()
            stderr = $p.StandardError.ReadToEnd()
            ExitCode = $p.ExitCode  
        }
    }
    else
    {
        # File not found
        return [pscustomobject]@{
            commandTitle = $commandTitle
            stdout = $null
            stderr = $null
            ExitCode = 99999
        }
    }
}


##########################################
### Function to install or remove HAPI ###
##########################################
Function InstallOrRemoveHapi
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [ValidateSet("Install","Remove")] 
        [string]$Action = "Install",

        [Parameter(Mandatory=$True,Position=2)]
        [string]$ThisScriptPath = $null
    )

    $iFuncRslt = -1   # Default

    # Determine architecture
    if ((TestPathQuiet -DirOrFile "$env:SystemDrive\Program Files (x86)") -eq $true)
    {
        # 64-bit
        $strHapintExe = "hapint64.exe"
    }
    else
    {
        # 32-bit
        $strHapintExe = "hapint.exe"
    }

    # Check if Hapint file exists
    $strHapintExeFullPath = "$ThisScriptPath\Command_Configure\X86_64\HAPI\$strHapintExe"
    if ((TestPathQuiet -DirOrFile $strHapintExeFullPath) -eq $true)
    {
        # File found, install or remove HAPI
        if ($Action -ieq "Install")
        {
            # Install HAPI
            $objHapintExeRslt = Execute-Command -commandTitle "HAPI Install" -commandPath $strHapintExeFullPath -commandArguments "-i -k C-C-T-K -p $strHapintExe"

            if ($objHapintExeRslt.ExitCode -eq 0)
            {
                # Install succeeded
                $iFuncRslt = 0
            }
            else
            {
                # Install failed
                $iFuncRslt = 2
            }
        }
        else
        {
            # Remove HAPI
            $objHapintExeRslt = Execute-Command -commandTitle "HAPI Uninstall" -commandPath $strHapintExeFullPath -commandArguments "-r -k C-C-T-K"

            if ($objHapintExeRslt.ExitCode -eq 0)
            {
                # Removal succeeded
                $iFuncRslt = 0
            }
            else
            {
                # Removal failed but could be because HAPI wasn't installed, so set result to 1 for a warning
                $iFuncRslt = 1
            }
        }
    }
    else
    {
        $iFuncRslt = 2    # Error, hapint .exe not found
    }


    return $iFuncRslt
}


###########################################
### Function to get the Dell boot order ###
###########################################
Function GetDellBootOrder
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [ValidateSet("legacy","uefi")] 
        [string]$BootListType="uefi",                              # Must be lowercase

        [Parameter(Mandatory=$True,Position=2)]
        [string]$CctkPath = $null
    )

    # Array to hold boot order for function result
    $arrObjCctkBootOrderDevices = @()

    # Get the current Dell boot order
    $objCctkBootOrder = Execute-Command -commandTitle "CCTK" -commandPath $strCctkFullPath -commandArguments "`"bootorder`" `"--bootlisttype=$BootListType`""
    $arrCctkBootOrder = $objCctkBootOrder.stdout -split "`r`n"   # Need to split stdout into an array since it's just a string

    # Get the hyphen lines which are immediately before and after the boot devices
    $arrCctkBootOrderHyphenLines = $arrCctkBootOrder | select-string "----------"

    if ($arrCctkBootOrderHyphenLines -ne $null -and @($arrCctkBootOrderHyphenLines).Count -eq 2)
    {
        # Found the two lines, get the select-string line numbers
        # Note: Output array starts at "0" but select-string LineNumber starts at "1"
        $iCctkBootOrderHyphenLine1Num = ($arrCctkBootOrderHyphenLines[0].LineNumber)
        $iCctkBootOrderHyphenLine2Num = ($arrCctkBootOrderHyphenLines[1].LineNumber) -2

        # Get the lines in between which are the boot devices
        $arrCctkBootOrderDevices = $arrCctkBootOrder[$iCctkBootOrderHyphenLine1Num..$iCctkBootOrderHyphenLine2Num]

        # Loop through devices and create objects
        foreach($strCctkBootOrderDevice in $arrCctkBootOrderDevices)
        {
            # Split to parse out columns
            $arrCctkBootOrderDeviceSplit = $strCctkBootOrderDevice -split "  " | where {$_.tostring().trim() -ne "" }

            # Make sure there are 5+ columns
            if ($arrCctkBootOrderDeviceSplit -ne $null -and $arrCctkBootOrderDeviceSplit.count -ge 5)
            {
                # Create a custom object to hold properties for each column
                $objCctkBootOrderDevice = New-Object psobject
                Add-Member -InputObject $objCctkBootOrderDevice -MemberType NoteProperty -Name DeviceStatus      -Value $arrCctkBootOrderDeviceSplit[0].tostring().trim()
                Add-Member -InputObject $objCctkBootOrderDevice -MemberType NoteProperty -Name DeviceNumber      -Value ([int]($arrCctkBootOrderDeviceSplit[1].tostring().trim()))
                Add-Member -InputObject $objCctkBootOrderDevice -MemberType NoteProperty -Name DeviceType        -Value $arrCctkBootOrderDeviceSplit[2].tostring().trim()
                Add-Member -InputObject $objCctkBootOrderDevice -MemberType NoteProperty -Name Shortform         -Value $arrCctkBootOrderDeviceSplit[3].tostring().trim()

                # Concatenate all remaining columns in case double spaces found in device description
                Add-Member -InputObject $objCctkBootOrderDevice -MemberType NoteProperty -Name DeviceDescription -Value ([string]::join("", ($arrCctkBootOrderDeviceSplit[4..($arrCctkBootOrderDeviceSplit.count-1)]))).tostring().trim()

                # Add current object to array of objects
                $arrObjCctkBootOrderDevices += $objCctkBootOrderDevice
            }
        }
    }

    # Return boot order
    return $arrObjCctkBootOrderDevices
}


############################################################
### Function to get a Dell BIOS setting value using CCTK ###
############################################################
Function GetDellBiosSetting
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$CctkPath = "",

        [Parameter(Mandatory=$True,Position=2)]
        [string]$CctkOptionName = ""
    )

    $iCctkOptionCurrentValueExitCode = 99999   # Default
    $strCctkOptionCurrentValue       = $null   # Default


    # Parse the rightmost "leaf" name from the option command, in case it's a sub-option
    $CctkOptionNameLeaf = $CctkOptionName -split " " | select -Last 1
    $CctkOptionNameLeaf = TrimQuotes -String $CctkOptionNameLeaf

    # Remove the leading one or two hyphens from the left name
    for ($i=1; $i -le 2; $i++)
    {
        if ($CctkOptionNameLeaf.substring(0, 1) -eq "-")
        {
            $CctkOptionNameLeaf = $CctkOptionNameLeaf.substring(1, $CctkOptionNameLeaf.length -1)
        }
    }

    # RegEx where start of line matches CCTK option name then "=", while ignoring whitespace
    $CctkValidValueRegEx = "^\s*$CctkOptionNameLeaf\s*="

    # Check current setting
    $objCctkOptionCurrentValue = Execute-Command -commandTitle "CCTK" -commandPath $CctkPath -commandArguments $CctkOptionName
    $arrCctkOptionCurrentValueOutput = $objCctkOptionCurrentValue.stdout -split "`r`n"   # Need to split stdout into an array since it's just a string
    $iCctkOptionCurrentValueExitCode = $objCctkOptionCurrentValue.ExitCode

    # Get RegEx value for CCTK option leaf name into a MatchInfo object
    $miCctkOptionRegExMatch = $arrCctkOptionCurrentValueOutput | select-string -Pattern $CctkValidValueRegEx

    if ($miCctkOptionRegExMatch -ne $null -and $iCctkOptionCurrentValueExitCode -eq 0)
    {
        # CCTK option leaf name found in output array, get value
        $strCctkOptionCurrentValue = ([string]($miCctkOptionRegExMatch.line -split $miCctkOptionRegExMatch.matches)[1]).Trim()
    }

    # Return result
    return [pscustomobject]@{
        CctkCurrentValue = $strCctkOptionCurrentValue
        CctkExitCode = $iCctkOptionCurrentValueExitCode
    }
}



#########################################################
### Function to update a Dell BIOS setting using CCTK ###
#########################################################
Function SetDellBiosSetting
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$CctkPath = "",

        [Parameter(Mandatory=$True,Position=2)]
        [string]$CctkOptionName = "",

        [Parameter(Mandatory=$True,Position=3)]
        [string]$CctkOptionNewValue = "",

        [Parameter(Mandatory=$False,Position=4)]
        [hashtable]$CctkErrorCodeLookupHashtable = @{}
    )

    <#
        Return codes:
       -1: Success - CCTK option value was originally the same as the desired setting so no update was attempted
        0: Success - CCTK option value was originally different vs. the desired setting but was successfully updated
        1: Error   - CCTK option value not found on first check
        2: Error   - CCTK option value not found on second check
        3: Error   - CCTK option value found but not updated
    #>

    $iFuncRslt = 99999   # Default

    
    # Call function to get current value
    $objCctkOptionValue = GetDellBiosSetting -CctkPath $CctkPath -CctkOptionName $CctkOptionName
    $strCctkOptionValue = $objCctkOptionValue.CctkCurrentValue
    $iCctkOptionExitCode = $objCctkOptionValue.CctkExitCode

    # Check if current value found
    if ($strCctkOptionValue -eq $null)
    {
        # CCTK value not found
        write-host "$((get-date).tostring()): ERROR: CCTK option `"$CctkOptionName`" desired value: $CctkOptionNewValue; current value not found (CCTK exit code: $iCctkOptionExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionExitCode))" -ForegroundColor Red
        write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: CCTK option `"$CctkOptionName`" desired value: $CctkOptionNewValue; current value not found (CCTK exit code: $iCctkOptionExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionExitCode))"
        $iFuncRslt = 1
    }
    else
    {
        # Compare original value with desired value
        if ($strCctkOptionValue.trim() -ieq $CctkOptionNewValue.trim() -and $iCctkOptionExitCode -eq 0)
        {
            # Matches
            write-host "$((get-date).tostring()): CCTK option `"$CctkOptionName`" already set to desired value: $strCctkOptionValue (CCTK exit code: $iCctkOptionExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionExitCode))"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): CCTK option `"$CctkOptionName`" already set to desired value: $strCctkOptionValue (CCTK exit code: $iCctkOptionExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionExitCode))"
            $iFuncRslt = -1
        }
        else
        {
            # Doesn't match
            write-host "$((get-date).tostring()): CCTK option `"$CctkOptionName`" desired value: $CctkOptionNewValue; current value: $strCctkOptionValue (CCTK exit code: $iCctkOptionExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionExitCode))"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): CCTK option `"$CctkOptionName`" desired value: $CctkOptionNewValue; current value: $strCctkOptionValue (CCTK exit code: $iCctkOptionExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionExitCode))"

            # Try updating value
            $objCctkOptionUpdate = Execute-Command -commandTitle "CCTK" -commandPath $strCctkFullPath -commandArguments "$CctkOptionName=$CctkOptionNewValue"
            $arrCctkOptionUpdate = $objCctkOptionUpdate.stdout -split "`r`n"   # Need to split stdout into an array since it's just a string
            $iCctkOptionUpdateExitCode = $objCctkOptionUpdate.ExitCode

            # Get the updated Dell value from the function instead of trying to duplicate logic here BUT use the CCTK exit code from the "update command"
            $objCctkOptionValue2 = GetDellBiosSetting -CctkPath $CctkPath -CctkOptionName $CctkOptionName
            $strCctkOptionValue2 = $objCctkOptionValue2.CctkCurrentValue
            $iCctkOptionExitCode2 = $objCctkOptionValue2.CctkExitCode

            # Check if updated value found
            if ($strCctkOptionValue2 -eq $null)
            {
                # CCTK value not found
                write-host "$((get-date).tostring()): ERROR: CCTK option `"$CctkOptionName`" desired value: $CctkOptionNewValue; updated value not found (CCTK update exit code: $iCctkOptionUpdateExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionUpdateExitCode))" -ForegroundColor Red
                write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: CCTK option `"$CctkOptionName`" desired value: $CctkOptionNewValue; updated value not found (CCTK update exit code: $iCctkOptionUpdateExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionUpdateExitCode))"
                $iFuncRslt = 2
            }
            else
            {
                # Compare updated value with desired value
                if ($strCctkOptionValue2.trim() -ieq $CctkOptionNewValue.trim() -and $iCctkOptionUpdateExitCode -eq 0)
                {
                    # Matches
                    write-host "$((get-date).tostring()): CCTK option `"$CctkOptionName`" updated to desired value: $strCctkOptionValue2 (CCTK update exit code: $iCctkOptionUpdateExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionUpdateExitCode))"
                    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): CCTK option `"$CctkOptionName`" updated to desired value: $strCctkOptionValue2 (CCTK update exit code: $iCctkOptionUpdateExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionUpdateExitCode))"
                    $iFuncRslt = 0
                }
                else
                {
                    # Doesn't match
                    write-host "$((get-date).tostring()): ERROR CCTK option `"$CctkOptionName`" NOT updated to desired value: $CctkOptionNewValue; updated value: $strCctkOptionValue2 (CCTK update exit code: $iCctkOptionUpdateExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionUpdateExitCode))" -ForegroundColor Red
                    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR CCTK option `"$CctkOptionName`" NOT updated to desired value: $CctkOptionNewValue; updated value: $strCctkOptionValue2 (CCTK update exit code: $iCctkOptionUpdateExitCode$($CctkErrorCodeLookupHashtable.$iCctkOptionUpdateExitCode))"
                    $iFuncRslt = 3
                }
            }
        }
    }


    # Return overall result
    return $iFuncRslt
}


############
### Main ###
############
$iOverallErrorCt   = 0  # Track number of errors
$iOverallWarningCt = 0  # Track number of warnings

# Generate a GUID and use the prefix to track related log entries
$strGuidPrefix = (([string][guid]::NewGuid()) -split "-")[0]

# Determine log file
if ($LogFile -ieq "<Default>")
{
    # Not specified, use log file in C:\Windows\Temp and based on script name
    $strLogfile = $env:SystemRoot + "\Temp\" + [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Definition) + ".log"
}
else
{
    $strLogfile = $LogFile
}


# Import the SCCM-compatible logging module
$strModuleFile = "$([System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition))\Logging.psm1"

$ImportRslt = $null
try { $ImportRslt = import-module $strModuleFile -PassThru -ErrorAction Stop }
catch {}

if ([bool]$ImportRslt -ne $true)
{
    write-host "$($strGuidPrefix): WARNING: Logging module not imported" -ForegroundColor Yellow
    $iOverallWarningCt++
}

# Update logfile that script started
$dtScriptStart = (get-date)                                                                                       # Used to calculate script duration
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Script started"

# If user name matches the computer name plus a trailing $ then it's the local System
$strUsername = $env:USERNAME

if ($strUsername -ieq ($env:COMPUTERNAME + "$"))
{
    $strUsername = "SYSTEM"
}

# Check if running as a local Admin
$bIsAdmin = IsAdmin

if ($bIsAdmin -eq $True)
{
    $strLogType = "Informational"
}
else
{
    $iOverallErrorCt++
    $strLogType = "Error"
} 

# Get computer name
$ComputerName = $env:COMPUTERNAME.ToUpper()

# Get last boot time in 'mm/dd/yyyy hh:mm:ss AMPM' format
$strLastBootTime = get-date ([System.Management.ManagementDateTimeconverter]::ToDateTime((gwmi -Query "Select * from Win32_OperatingSystem").LastBootupTime)) -UFormat '%m/%d/%Y %I:%M:%S %p'

# Get full path to current script and directory, which is required for some functions
$strThisScript = $MyInvocation.MyCommand.Definition
$strThisScriptPath = [System.IO.Path]::GetDirectoryName($strThisScript)

$BootListType = $BootListType.ToLower()  # CCTK requires lowercase


#----------------------------#
# Update log with basic info #
#----------------------------#
write-host "$((get-date).tostring()): Log File: $strLogfile"
write-host "$((get-date).tostring()): Computer Name: $ComputerName"
write-host "$((get-date).tostring()): User Name: $strUsername"

if ($bIsAdmin -eq $True)
{
    write-host "$((get-date).tostring()): User is an Admin: $bIsAdmin"
}
else
{
    write-host "$((get-date).tostring()): ERROR: User is an Admin: $bIsAdmin" -ForegroundColor Red
} 

write-host "$((get-date).tostring()): Last Boot Time: $strLastBootTime"
write-host "$((get-date).tostring()): Log Max Size (bytes): $MaxLogSizeBytes"
write-host "$((get-date).tostring()): BootListType: $BootListType"
write-host "$((get-date).tostring()): DisableMatchingDevices: $DisableMatchingDevices"
write-host "$((get-date).tostring()): FilterDeviceDescription: $FilterDeviceDescription"
write-host "$((get-date).tostring()): FilterDeviceNumber: $FilterDeviceNumber"
write-host "$((get-date).tostring()): FilterDeviceStatus: $FilterDeviceStatus"
write-host "$((get-date).tostring()): FilterDeviceType: $FilterDeviceType"
write-host "$((get-date).tostring()): FilterShortform: $FilterShortform"
write-host "$((get-date).tostring()): IncludeAllRemainingBootDevices: $IncludeAllRemainingBootDevices"
write-host "$((get-date).tostring()): SkipHapiPreinstall: $SkipHapiPreinstall"
write-host "$((get-date).tostring()): SkipHapiRemoval: $SkipHapiRemoval"
write-host "$((get-date).tostring()): SortFilterMatchesDescending: $SortFilterMatchesDescending"

write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Log file: $strLogfile"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Computer Name: $ComputerName"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): User Name: $strUsername"
write-log -FilePath $strLogfile -Type $strLogType   -Message "$($strGuidPrefix): User is an Admin: $bIsAdmin"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Last Boot Time: $strLastBootTime"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Log Max Size (bytes): $MaxLogSizeBytes"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): BootListType: $BootListType"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): DisableMatchingDevices: $DisableMatchingDevices"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): FilterDeviceDescription: $FilterDeviceDescription"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): FilterDeviceNumber: $FilterDeviceNumber"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): FilterDeviceStatus: $FilterDeviceStatus"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): FilterDeviceType: $FilterDeviceType"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): FilterShortform: $FilterShortform"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): IncludeAllRemainingBootDevices: $IncludeAllRemainingBootDevices"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): SkipHapiPreinstall: $SkipHapiPreinstall"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): SkipHapiRemoval: $SkipHapiRemoval"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): SortFilterMatchesDescending: $SortFilterMatchesDescending"


#--------------------------------------------------------#
# Preinstall HAPI to speed up multiple calls to cctk.exe #
#--------------------------------------------------------#
if ($SkipHapiPreinstall -eq $False)
{
    $iHapiRslt = InstallOrRemoveHapi -Action Install -ThisScriptPath $strThisScriptPath

    # Record result
    if ($iHapiRslt -eq 0)
    {
        write-host "$((get-date).tostring()): HAPI pre-install succeeded ($iHapiRslt)"
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): HAPI pre-install succeeded ($iHapiRslt)"
    }
    else
    {
        write-host "$((get-date).tostring()): ERROR: HAPI pre-install failed ($iHapiRslt)" -ForegroundColor Red
        write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: HAPI pre-install failed ($iHapiRslt)"
        $iOverallErrorCt++
    } 
}


#------------------------#
# Verify CCTK.exe exists #
#------------------------#
$strCctkFullPath = "$strThisScriptPath\Command_Configure\X86_64\cctk.exe"

if ((TestPathQuiet -DirOrFile $strCctkFullPath) -eq $true)
{
    # File found
    write-host "$((get-date).tostring()): File found: $strCctkFullPath"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): File found: $strCctkFullPath"
}
else
{
    # File not found
    write-host "$((get-date).tostring()): ERROR: File not found: $strCctkFullPath" -ForegroundColor Red
    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: File not found: $strCctkFullPath"
    $iOverallErrorCt++
}


#------------------------------------------------------------------------#
# Load the CCTK error codes file to help resolve to friendly description #
#------------------------------------------------------------------------#
$htCctkErrorCodeLookup = @{}   # Create empty hashtable

$strCctkErrorCodeLookupFile = "$strThisScriptPath\CCTK_Error_Codes.txt"

# Verify lookup file exists
if ((TestPathQuiet -DirOrFile $strCctkErrorCodeLookupFile) -eq $true)
{
    # File found
    write-host "$((get-date).tostring()): File found: $strCctkErrorCodeLookupFile"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): File found: $strCctkErrorCodeLookupFile"

    # Load into a MatchInfo object array where line starts with a number
    $arrMiCctkErrorCodeLookup = get-content $strCctkErrorCodeLookupFile -Encoding Ascii | select-string "^\s*\d+.\s*"

    # Loop through MatchInfo object array
    foreach ($objMiCctkErrorCodeLookup in $arrMiCctkErrorCodeLookup)
    {
        # Parse current MatchInfo line and use number as key
        $iCctkErrorCodeLookupKey = [int]($objMiCctkErrorCodeLookup.matches.value)
        $strCctkErrorCodeLookup  = [string](($objMiCctkErrorCodeLookup.line -split ($objMiCctkErrorCodeLookup.matches.value))[1])
        
        # Surround result with brackets if at least one character long, to help with formatting during output/logging
        if ($strCctkErrorCodeLookup.Length -ge 1)
        {
            $strCctkErrorCodeLookup = " [$strCctkErrorCodeLookup]"
        }

        # Add to hashtable
        $htCctkErrorCodeLookup.Add($iCctkErrorCodeLookupKey, $strCctkErrorCodeLookup)
    }
}
else
{
    # File not found
    write-host "$((get-date).tostring()): WARNING: File not found: $strCctkErrorCodeLookupFile" -ForegroundColor Yellow
    write-log -FilePath $strLogfile -Type Warning -Message "$($strGuidPrefix): WARNING: File not found: $strCctkErrorCodeLookupFile"
    $iOverallWarningCt++
}


#------------------------------------------------#
# Get current boot order and determine new order #
#------------------------------------------------#
$arrObjCctkBootOrderDevices = GetDellBootOrder -BootListType $BootListType -CctkPath $strCctkFullPath
write-host "`n`nORIGINAL BOOT ORDER:" -ForegroundColor Yellow
$arrObjCctkBootOrderDevices | ft -AutoSize

# Output original order to log
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): ORIGINAL BOOT ORDER:"

$iCurrBootOrderDeviceIdx = 0
foreach ($objObjCctkBootOrderDevice in $arrObjCctkBootOrderDevices)
{
    $iCurrBootOrderDeviceIdx++
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): ($iCurrBootOrderDeviceIdx) $objObjCctkBootOrderDevice"
}

# Get device numbers that match the filters
$arrCctkBootOrderDeviceIDs = @()
$arrCctkBootOrderDeviceIDs = @($arrObjCctkBootOrderDevices | where {$_.DeviceDescription -match $FilterDeviceDescription -and $_.DeviceNumber -match $FilterDeviceNumber -and $_.DeviceStatus -match $FilterDeviceStatus -and $_.DeviceType -match $FilterDeviceType -and $_.Shortform -match $FilterShortform} | sort DeviceNumber | select -ExpandProperty DeviceNumber)

# Sort devices that matched filters in descending order, if specified
if ($SortFilterMatchesDescending -eq $true)
{
    $arrCctkBootOrderDeviceIDs = $arrCctkBootOrderDeviceIDs | sort -Descending
}

# Add in all remaining devices, if specified
if ($IncludeAllRemainingBootDevices -eq $true)
{
    $arrCctkBootOrderDeviceIDs += $arrObjCctkBootOrderDevices.DeviceNumber
}

# Remove duplicates
$arrCctkBootOrderDeviceIDs = $arrCctkBootOrderDeviceIDs | Select-Object -Unique

# Join matching boot device ID sequence into string
if ($arrCctkBootOrderDeviceIDs -eq $null -or @($arrCctkBootOrderDeviceIDs).count -eq 0)
{
    # No matching boot device IDs
    write-host "$((get-date).tostring()): ERROR: No boot devices matched filters" -ForegroundColor Red
    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: No boot devices matched filters"
    $iOverallErrorCt++
}
else
{
    # Join matching boot device IDs
    $strCctkBootOrderDeviceIDs = [string]::join(",", $arrCctkBootOrderDeviceIDs)
    write-host "$((get-date).tostring()): Matching boot device numbers to order first: $strCctkBootOrderDeviceIDs"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Matching boot device numbers to order first: $strCctkBootOrderDeviceIDs"
}


#-------------------------------------#
# Update boot order and verify result #
#-------------------------------------#
if ($DisableMatchingDevices -eq $true)
{
    # Disable matching boot devices
    $strMatchingDeviceDesiredState = "DISABLED"
    $strMatchingDeviceDesiredStateCctkAction = "disabledevice"
}
else
{
    # Enable matching boot devices
    $strMatchingDeviceDesiredState = "ENABLED"
    $strMatchingDeviceDesiredStateCctkAction = "enabledevice"
}


# Update boot order
$objCctkBootOrder2 = Execute-Command -commandTitle "CCTK" -commandPath $strCctkFullPath -commandArguments "`"bootorder`" `"--bootlisttype=$BootListType`" `"--sequence=$strCctkBootOrderDeviceIDs`" `"--$strMatchingDeviceDesiredStateCctkAction=$strCctkBootOrderDeviceIDs`""
$arrCctkBootOrder2 = $objCctkBootOrder2.stdout -split "`r`n"   # Need to split stdout into an array since it's just a string

# Recheck the boot order to verify changes were successful
$arrObjCctkBootOrderDevices2 = GetDellBootOrder -BootListType $BootListType -CctkPath $strCctkFullPath
write-host "`n`nUPDATED BOOT ORDER:" -ForegroundColor Yellow
$arrObjCctkBootOrderDevices2 | ft -AutoSize
write-host ""

# Output updated order to log
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): UPDATED BOOT ORDER:"

$iCurrBootOrderDeviceIdx2 = 0
foreach ($objObjCctkBootOrderDevice2 in $arrObjCctkBootOrderDevices2)
{
    $iCurrBootOrderDeviceIdx2++
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): ($iCurrBootOrderDeviceIdx2) $objObjCctkBootOrderDevice2"
}


# Join updated boot device ID sequence into string
$arrCctkBootOrderDeviceIDs2 = $arrObjCctkBootOrderDevices2.DeviceNumber

if ($arrCctkBootOrderDeviceIDs2 -eq $null)
{
    # No matching boot device IDs
    write-host "$((get-date).tostring()): ERROR: No boot devices found during re-check" -ForegroundColor Red
    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: No boot devices found during re-check"
    $iOverallErrorCt++
}
else
{
    # Join matching boot device IDs
    $strCctkBootOrderDeviceIDs2 = [string]::join(",", $arrCctkBootOrderDeviceIDs2)
    write-host "$((get-date).tostring()): Updated boot device numbers order: $strCctkBootOrderDeviceIDs2"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Updated boot device numbers order: $strCctkBootOrderDeviceIDs2"    
}


# Compare matching and updated boot device ID list to determine result
if (($strCctkBootOrderDeviceIDs -ne $null) -and ($strCctkBootOrderDeviceIDs2 -ne $null) -and ($strCctkBootOrderDeviceIDs2.length -ge $strCctkBootOrderDeviceIDs.length) -and ($strCctkBootOrderDeviceIDs2.substring(0, $strCctkBootOrderDeviceIDs.length) -eq $strCctkBootOrderDeviceIDs))
{
    # Updated boot device number list begins with or equals matching boot device number list
    write-host "$((get-date).tostring()): Updated boot device number list begins with or equals matching boot device number list"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Updated boot device number list begins with or equals matching boot device number list"
}
else
{
    # Updated boot device number list doesn't begin with or equal matching boot device number list
    write-host "$((get-date).tostring()): ERROR: Updated boot device number list doesn't begin with or equal matching boot device number list" -ForegroundColor Red
    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: Updated boot device number list doesn't begin with or equal matching boot device number list"
    $iOverallErrorCt++
}


#------------------------------------------------------------------#
# Make sure matching boot devices are Enabled or Disabled properly #
#------------------------------------------------------------------#
$arrCctkBootOrderDeviceIDs2StateNotCorrect = $arrObjCctkBootOrderDevices2 | where {$_.DeviceNumber -in @($arrCctkBootOrderDeviceIDs) -and $_.DeviceStatus -ine $strMatchingDeviceDesiredState}

if (@($arrCctkBootOrderDeviceIDs2StateNotCorrect).Count -eq 0)
{
    # All matching boot devices in desired state
    write-host "$((get-date).tostring()): All matching boot devices in $strMatchingDeviceDesiredState state"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): All matching boot devices in $strMatchingDeviceDesiredState state"
}
else
{
    # One or more matching boot devices not in desired state
    write-host "ERROR: One or more matching boot devices not in $strMatchingDeviceDesiredState state:" -ForegroundColor Red
    $arrCctkBootOrderDeviceIDs2StateNotCorrect | ft -AutoSize
    
    # Output to log
    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: One or more matching boot devices not in $strMatchingDeviceDesiredState state:"

    $iCurrBootOrderDeviceStateNotCorrectIdx = 0
    foreach ($objCctkBootOrderDeviceIDs2StateNotCorrect in $arrCctkBootOrderDeviceIDs2StateNotCorrect)
    {
        $iCurrBootOrderDeviceStateNotCorrectIdx++
        write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ($iCurrBootOrderDeviceStateNotCorrectIdx) $objCctkBootOrderDeviceIDs2StateNotCorrect"
        $iOverallErrorCt++
    }
}


#--------------------------------------------------------#
# Set the active boot list to the specified BootListType #
#--------------------------------------------------------#
$iSetCctkRslt = SetDellBiosSetting -CctkPath $strCctkFullPath -CctkOptionName "bootorder --activebootlist" -CctkOptionNewValue $BootListType -CctkErrorCodeLookupHashtable $htCctkErrorCodeLookup

# If function return code is >= 1 then there was an error
if ($iSetCctkRslt -ge 1)
{
    $iOverallErrorCt++
}


#-------------#
# Remove HAPI #
#-------------#
if ($SkipHapiRemoval -eq $False)
{
    $iHapiRslt = InstallOrRemoveHapi -Action Remove -ThisScriptPath $strThisScriptPath
    
    # Record result
    if ($iHapiRslt -eq 0)
    {
        write-host "$((get-date).tostring()): HAPI removal succeeded ($iHapiRslt)"
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): HAPI removal succeeded ($iHapiRslt)"
    }
    else
    {
        write-host "$((get-date).tostring()): WARNING: HAPI removal failed but may have not been installed ($iHapiRslt)" -ForegroundColor Yellow
        write-log -FilePath $strLogfile -Type Warning -Message "$($strGuidPrefix): WARNING: HAPI removal failed but may have not been installed ($iHapiRslt)"
        $iOverallWarningCt++
    } 
}


#-------------------------------------#
# Trim the log file if the max log >0 #
#-------------------------------------#
if ($MaxLogSizeBytes -gt 0)
{
    $strTrimTextFileBlockRslt = TrimTextFileBlock -LogFile $strLogfile -MaxSizeBytes $MaxLogSizeBytes -TrimOnOverageLineIfNoBlockFound
    write-host "$((get-date).tostring()): Trim log result: $strTrimTextFileBlockRslt"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Trim log result: $strTrimTextFileBlockRslt"
}


################
### Finished ###
################
$dtScriptStop = (get-date)            # Used to calculate script duration
$dtScriptDuration = ($dtScriptStop - $dtScriptStart)
$strScriptDuration = [string]$dtScriptDuration.Days + "d " + $dtScriptDuration.Hours + "h " + $dtScriptDuration.Minutes + "m " + [int]($dtScriptDuration.Seconds + .49) + "s"

Write-Host "`n`nScript started: " $dtScriptStart
Write-Host "Script stopped: " $dtScriptStop
write-host "Script duration: $strScriptDuration"


write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Script started: $dtScriptStart"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Script stopped: $dtScriptStop"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Script duration: $strScriptDuration"


if ($iOverallErrorCt -eq 0 -and $iOverallWarningCt -eq 0)
{
    $iExitCode = 0
    write-host "`n$((get-date).tostring()): Script finished successfully (exit code: $iExitCode)"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Script finished successfully (exit code: $iExitCode)"
}
else
{
    if ($iOverallErrorCt -eq 0)
    {
        $iExitCode = 1   # Warning(s) but no errors
        $strLogType = "Warning"
        $strTextColor = "Yellow"
    }
    else
    {
        $iExitCode = 2   # At least one error
        $strLogType = "Error"
        $strTextColor = "Red"
    }
    
    write-host "`n$((get-date).tostring()): Script finished with $iOverallWarningCt warning(s) and $iOverallErrorCt error(s) (exit code: $iExitCode)" -ForegroundColor $strTextColor
    write-log -FilePath $strLogfile -Type $strLogType -Message "$($strGuidPrefix): Script finished with $iOverallWarningCt warning(s) and $iOverallErrorCt error(s) (exit code: $iExitCode)"
}

exit($iExitCode)
