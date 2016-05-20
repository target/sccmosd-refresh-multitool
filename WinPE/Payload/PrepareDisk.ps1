# Filename:      PrepareDisk.ps1
# Version:       1.2
# Description:   Formats the first fixed hard disk as a GPT or MBR disk type unless a "block file" is found or already using desired disk type
# Author:        Kent Vareberg, Desktop and Hardware Engineering


<#
.Synopsis
    Formats the first fixed hard disk as a GPT or MBR disk type unless a "block file" is found or already using desired disk type.


.Description
    Formats the first fixed hard disk as a GPT or MBR disk type unless a "block file" is found or already using desired disk type.

    See the PARAMETERS and NOTES sections for more information.


.Parameter BlockFiles
    Default is none.  Specify an array of one or more files that, if found, will block the disk format.  If no BlockFiles are specified then disk will always be formatted using specified BootDiskType.

.Parameter BootDiskType
    Default is "GPT".  Options are "GPT" or "MBR".

.Parameter ForceFormat
    Default is to only format the first fixed hard disk if NONE of the specified BlockFiles are found OR the first fixed hard disk doesn't match the BootDiskType.  This parameter will format the first fixed hard disk regardless of these two items.
        
.Parameter LogFile
    Default is %SystemDrive%\Windows\Temp\<ScriptBaseName>.log

.Parameter MaxLogSizeBytes
    Default is 5 MB; specify 0 to let grow indefinitely.


.Example
    This example formats the first fixed hard disk to MBR:

    PrepareDisk.ps1 -BootDiskType MBR

.Example
    This example formats the first fixed hard disk to GPT unless the disk type is already GPT AND either of the BlockFiles are found:

    PrepareDisk.ps1 -BootDiskType GPT -BlockFiles C:\_SMSTaskSequence\tsenv.dat,c:\temp\testfile.txt


.Notes
    -This script must be executed from an elevated PowerShell process.

    -The Logging.psm1 module must be in the same folder as this script to generate a CMTrace-compatible log file.

    -By default, if ANY of the specified BlockFiles are found AND the first fixed hard disk already matches the BootDiskType then disk will NOT be formatted.  The -ForceFormat parameter will format regardless of these two items.

    -If the current disk type doesn't match the specified boot type then the disk will be formatted.

    -The format will fail if trying to format the currently-booted hard disk unless it's a RAM disk (WinPE).
    
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
    [ValidateSet("GPT","MBR")] 
    [string]$BootDiskType ="GPT",

    [Parameter(Mandatory=$false)]
    [string[]]$BlockFiles = @(),

    [Parameter(Mandatory=$false)]
    [switch]$ForceFormat,

    [Parameter(Mandatory=$false)]
    [string]$LogFile = "<Default>",

    [Parameter(Mandatory=$false)]
    [int]$MaxLogSizeBytes=(5 * 1024 * 1024)
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


###################################################
### Function to test a path and suppress errors ###
###################################################
Function GetHardDiskType
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$DiskPartPath = "",
        
        [Parameter(Mandatory=$True,Position=2)]
        [int]$DiskIndex = 0,

        [Parameter(Mandatory=$False,Position=3)]
        [hashtable]$DiskPartExitCodeLookupHashtable = @{}
    )

    $strDiskType = "<Default>"   # Default


    # DiskPart file content to list disks
    $strDiskPartListDiskFile = "$env:TEMP\DiskPart_ListDisk.txt"
    "list disk" | Out-File $strDiskPartListDiskFile -Encoding ascii -Force

    # Execute DiskPart.exe to get disk info and determine type
    $objDiskPartRslt = Execute-Command -commandTitle "DiskPart" -commandPath $DiskPartPath -commandArguments "/s $strDiskPartListDiskFile"
    $arrDiskPartOutput = $objDiskPartRslt.stdout -split "`r`n"   # Need to split stdout into an array since it's just a string
    $iDiskPartExitCode = $objDiskPartRslt.ExitCode
    
    # Resolve the DiskPart exit code to a description
    $strDiskPartExitCodeDesc = $DiskPartExitCodeLookupHashtable.$iDiskPartExitCode

    if ($strDiskPartExitCodeDesc -eq $null -or $strDiskPartExitCodeDesc.trim() -eq "")
    {
        $strDiskPartExitCodeDesc = "Unknown"
    }

    # Get a MatchInfo object based on a RegEx to find the selected disk
    $miDiskPartSelectedDisk = $arrDiskPartOutput | select-string "^\s*Disk $DiskIndex"

    # Check DiskPart results
    if ($miDiskPartSelectedDisk -eq $null)
    {
        # Error disk not found
        $strDiskType = "<Not Found>"
    }
    else
    {
        # Disk found, check if GPT, based on asterisk as last character
        $strDiskPartSelectedDisk = ([string]$miDiskPartSelectedDisk).Trim()

        if ($strDiskPartSelectedDisk.Substring($strDiskPartSelectedDisk.Length -1, 1) -eq "*")
        {
            # Is GPT
            $strDiskType = "GPT"
        }
        else
        {
            # Isn't GPT
            $strDiskType = "MBR"
        }
    }

    return [pscustomobject]@{
        DiskPartExitCode = $iDiskPartExitCode
        DiskPartExitCodeDesc = $strDiskPartExitCodeDesc
        DiskType = $strDiskType
    }
}


############################################################################
### Function to get disks, respective partitions, and respective volumes ###
############################################################################
Function GetDiskPartitionVolumeMappings
{
    # Array to hold boot order for function result
    $arrobjDiskPartVolMapping = @()

    # Get all disk drives
    $arrDiskDrives = $null
    try { $arrDiskDrives = @(gwmi Win32_DiskDrive -ErrorAction Stop | sort Index) }
    catch {}

    # Loop through each disk drive
    foreach ($objDisk in $arrDiskDrives)
    {
        # Search for partitions associated with the current disk drive
        $strPartQuery = 'ASSOCIATORS OF {Win32_DiskDrive.DeviceID="' + $objDisk.DeviceID.replace('\','\\') + '"} WHERE AssocClass=Win32_DiskDriveToDiskPartition'
 
        $arrPartitions = $null
        try { $arrPartitions = @(gwmi -query $strPartQuery -ErrorAction Stop | sort StartingOffset) }
        catch {}

        # Loop through each partition
        foreach ($objPartition in $arrPartitions)
        {
            # Search for volumes associated with the current partition
            $strVolQuery = 'ASSOCIATORS OF {Win32_DiskPartition.DeviceID="' + $objPartition.DeviceID + '"} WHERE AssocClass=Win32_LogicalDiskToPartition'
        
            $arrVolumes = $null
            try { $arrVolumes = @(gwmi -query $strVolQuery -ErrorAction Stop | sort Name) }
            catch {}
 
            # Loop through each volume
            foreach ($objVolume in $arrVolumes)
            {
                # Create a custom object to hold properties for each column
                $objDiskPartVolMapping = New-Object psobject
                Add-Member -InputObject $objDiskPartVolMapping -MemberType NoteProperty -Name DiskIndex      -Value $objDisk.Index
                Add-Member -InputObject $objDiskPartVolMapping -MemberType NoteProperty -Name PartitionIndex -Value $objPartition.Index
                Add-Member -InputObject $objDiskPartVolMapping -MemberType NoteProperty -Name VolumeName     -Value $objVolume.Name

                # Add current object to array of objects
                $arrobjDiskPartVolMapping += $objDiskPartVolMapping
            }
        }
    }

    return $arrobjDiskPartVolMapping
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

$BootDiskType = $BootDiskType.ToUpper()


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
write-host "$((get-date).tostring()): BootDiskType: $BootDiskType"
write-host "$((get-date).tostring()): BlockFiles ($(@($BlockFiles).Count)): $([string]::Join(", ", $BlockFiles))"
write-host "$((get-date).tostring()): ForceFormat: $ForceFormat"

write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Log file: $strLogfile"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Computer Name: $ComputerName"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): User Name: $strUsername"
write-log -FilePath $strLogfile -Type $strLogType   -Message "$($strGuidPrefix): User is an Admin: $bIsAdmin"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Last Boot Time: $strLastBootTime"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Log Max Size (bytes): $MaxLogSizeBytes"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): BootDiskType: $BootDiskType"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): BlockFiles ($(@($BlockFiles).Count)): $([string]::Join(", ", $BlockFiles))"
write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): ForceFormat: $ForceFormat"


#-----------------------------------------#
# Find DiskPart.exe based on architecture #
#-----------------------------------------#
# Determine architecture
if ((TestPathQuiet -DirOrFile "$env:SystemDrive\Program Files (x86)") -eq $true)
{
    # 64-bit
    $strDiskPartExe = "$env:SystemRoot\System32\DiskPart.exe"
}
else
{
    # 32-bit
    $strDiskPartExe = "$env:SystemRoot\SysWOW64\DiskPart.exe"
}

if ((TestPathQuiet -DirOrFile $strDiskPartExe) -eq $true)
{
    # File found
    write-host "$((get-date).tostring()): File found: $strDiskPartExe"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): File found: $strDiskPartExe"
}
else
{
    # File not found
    write-host "$((get-date).tostring()): ERROR: File not found: $strDiskPartExe" -ForegroundColor Red
    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: File not found: $strDiskPartExe"
    $iOverallErrorCt++
}


#-------------------------------------------------------#
# Resolve DiskPart exit codes to a friendly description #
#-------------------------------------------------------#
$htDiskPartExitCodeLookup = @{}   # Create empty hashtable

# Use here-string to simplify list of error codes (refer to https://technet.microsoft.com/en-us/library/bb490893.aspx)
$strDiskPartExitCodes = @"
0. No errors occurred. The entire script ran without failure.
1. A fatal exception occurred. There may be a serious problem.
2. The parameters specified for a DiskPart command were incorrect.
3. DiskPart was unable to open the specified script or output file.
4. One of the services DiskPart uses returned a failure.
5. A command syntax error occurred. The script failed because an object was improperly selected or was invalid for use with that command.
"@

$arrDiskPartExitCodes = $strDiskPartExitCodes -split "`r`n"   # Need to split here-string into an array

# Load into a MatchInfo object array where line starts with a number
$arrMiDiskPartExitCodeLookup = $arrDiskPartExitCodes | select-string "^\s*\d+.\s*"

# Loop through MatchInfo object array
foreach ($objMiDiskPartExitCodeLookup in $arrMiDiskPartExitCodeLookup)
{
    # Parse current MatchInfo line and use number as key
    $iDiskPartExitCodeLookupKey = [int]($objMiDiskPartExitCodeLookup.matches.value)
    $strDiskPartExitCodeLookup  = [string](($objMiDiskPartExitCodeLookup.line -split ($objMiDiskPartExitCodeLookup.matches.value))[1])

    # Add to hashtable
    $htDiskPartExitCodeLookup.Add($iDiskPartExitCodeLookupKey, $strDiskPartExitCodeLookup)
}


#------------------------------------------------------#
# Create the DiskPart format disk script based on type #
#------------------------------------------------------#
# DiskPart file content as here-strings, as they don't format properly within "if" block
$strDiskPartFormatMbrContent = @"
clean
create partition primary
format quick fs=ntfs label="Windows"
assign letter="C"
"@

$strDiskPartFormatGptContent = @"
clean
convert gpt
create partition efi size=512
format quick fs=fat32 label="System"
assign letter="S"
create partition msr size=128
create partition primary
format quick fs=ntfs label="Windows"
assign letter="C"
"@

# Select respective here-string based on option
if ($BootDiskType -ieq "MBR")
{
    # Use MBR
    $strDiskPartFormatContent = $strDiskPartFormatMbrContent
}
else
{
    # Use GPT
    $strDiskPartFormatContent = $strDiskPartFormatGptContent
}


#--------------------------------------------#
# Get the index of the first fixed hard disk #
#--------------------------------------------#
$arrFixedHardDisks = $null
try {$arrFixedHardDisks = @(gwmi -Query "select * from Win32_DiskDrive where MediaType like 'Fixed hard disk%'" -ErrorAction Stop | select -ExpandProperty Index | sort) }
catch {}

if ($arrFixedHardDisks -eq $null -or $arrFixedHardDisks.Count -eq 0)
{
    # No fixed hard disks found    
    write-host "$((get-date).tostring()): ERROR: No fixed hard disks found" -ForegroundColor Red
    write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: No fixed hard disks found"
    $iOverallErrorCt++
}
else
{
    # Found one or more fixed hard disks
    write-host "$((get-date).tostring()): Found $($arrFixedHardDisks.count) fixed hard disks with index numbers: $([string]::join(", ", $arrFixedHardDisks))"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Found $($arrFixedHardDisks.count) fixed hard disks with index numbers: $([string]::join(", ", $arrFixedHardDisks))"


    #-----------------------------------------------#
    # Check drive letters associated with each disk #
    #-----------------------------------------------#
    # String to hold DiskPart format script drive letter re-mappings
    $strDiskPartFormatDriveLetterRemappings = ""


    # Get drive letters in-use
    $arrDriveLettersInUse = $null
    try { $arrDriveLettersInUse = @(gwmi win32_logicaldisk | Select-Object -ExpandProperty Name | sort) }
    catch {}

    $lstDriveLettersNotInUse = [System.Collections.Generic.List[System.Object]]($arrDriveLettersValid | where {$_ -notin $arrDriveLettersInUse})  # Use a List to help with removing elements later
    write-host "$((get-date).tostring()): Drive letters in-use: $([string]::join(" ", $arrDriveLettersInUse))"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Drive letters in-use: $([string]::join(" ", $arrDriveLettersInUse))"


    # Create an array of drive letters from C: through Z:
    $arrDriveLettersValid = @(); for ($i=67; $i -le 90; $i++) { $arrDriveLettersValid += "$([char]$i):" }


    # Get all disks with respective partitions and volumes        
    $arrobjDiskPartVolMapping = GetDiskPartitionVolumeMappings


    # Show volumes associated with all fixed hard disks
    foreach ($iFixedHardDisk in $arrFixedHardDisks)
    {
        # Get volumes on current fixed disk
        $arrCurrDiskVolumes = @($arrobjDiskPartVolMapping | where {$_.DiskIndex -eq $iFixedHardDisk} | select -ExpandProperty VolumeName | sort)
        write-host "$((get-date).tostring()): Volumes on fixed hard disk `"Disk $iFixedHardDisk`": $([string]::join(" ", $arrCurrDiskVolumes))"
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Volumes on fixed hard disk `"Disk $iFixedHardDisk`": $([string]::join(" ", $arrCurrDiskVolumes))"
    }


    # Get volumes not on fixed hard disks (should be removable disks)
    $arrNonFixedDiskVolumes = @($arrobjDiskPartVolMapping | where {$_.DiskIndex -notin @($arrFixedHardDisks)} | select -ExpandProperty VolumeName | sort)
    write-host "$((get-date).tostring()): Volumes other than on fixed hard disks: $([string]::join(" ", $arrNonFixedDiskVolumes))"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Volumes other than on fixed hard disks: $([string]::join(" ", $arrNonFixedDiskVolumes))"


    # Get volumes on first fixed disk
    $iFirstDiskIndex = @($arrFixedHardDisks)[0]
    $arrFirstDiskVolumes = @($arrobjDiskPartVolMapping | where {$_.DiskIndex -eq $iFirstDiskIndex} | select -ExpandProperty VolumeName | sort)


    # Get drive letters in-use but not by a fixed hard disk
    $arrDriveLettersInUseNotFixedHardDisks = @($arrDriveLettersInUse | where {$_ -notin @($arrobjDiskPartVolMapping.VolumeName)} | sort)
    write-host "$((get-date).tostring()): Non-disk drive letters in-use: $([string]::join(" ", $arrDriveLettersInUseNotFixedHardDisks))"
    write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Non-disk drive letters in-use: $([string]::join(" ", $arrDriveLettersInUseNotFixedHardDisks))"
        

    # Get drive letters to be used in the DiskPart format script
    $arrDriveLettersInDiskPartScript = @()     # String array to hold parsed drive letters from DiskPart script
    $arrMiDriveLettersInDiskPartScriptRegEx = $strDiskPartFormatContent -split "`r`n" | select-string "^\s*assign letter\s*=\s*"   # Get lines starting with "assign letter="
    
    foreach ($objMiDriveLettersInDiskPartScriptRegEx in $arrMiDriveLettersInDiskPartScriptRegEx)
    {
        # Get the value from each MatchInfo object, remove quotes, and ensure it ends with a colon
        $strCurrDriveLetterInDiskPartScript = ([string]($objMiDriveLettersInDiskPartScriptRegEx.line -split $objMiDriveLettersInDiskPartScriptRegEx.matches)[1]).Trim().ToUpper()
        $strCurrDriveLetterInDiskPartScript = [string](TrimQuotes -String $strCurrDriveLetterInDiskPartScript).replace(":","") + ":"
        $arrDriveLettersInDiskPartScript += $strCurrDriveLetterInDiskPartScript  # Add to array
    }

    $arrDriveLettersInDiskPartScript = $arrDriveLettersInDiskPartScript | sort -Unique


    # Determine if any drive letters to be used in the DiskPart format script are on disks OTHER than the first fixed hard disk and are currently in-use
    $arrDiskPartDriveLettersNotOnFirstHardDisk = @($arrDriveLettersInDiskPartScript | where {$_ -notin $arrFirstDiskVolumes -and $_ -in $arrDriveLettersInUse})

    if ($arrDiskPartDriveLettersNotOnFirstHardDisk.count -eq 0)
    {
        # No in-use DiskPart drive letters found outside of first fixed hard disk
        write-host "$((get-date).tostring()): No DiskPart format script drive letters ($([string]::join(" ", $arrDriveLettersInDiskPartScript))) are in-use and outside of `"Disk $iFirstDiskIndex`""
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): No DiskPart format script drive letters ($([string]::join(" ", $arrDriveLettersInDiskPartScript))) are in-use and outside of `"Disk $iFirstDiskIndex`""
    }
    else
    {
        # One or more DiskPart drive letters in-use and found outside of first fixed hard disk
        write-host "$((get-date).tostring()): WARNING: The following DiskPart format script drive letters are not used on `"Disk $iFirstDiskIndex`": $([string]::join(" ", $arrDiskPartDriveLettersNotOnFirstHardDisk))" -ForegroundColor Yellow
        write-log -FilePath $strLogfile -Type Warning -Message "$($strGuidPrefix): WARNING: The following DiskPart format script drive letters are not used on `"Disk $iFirstDiskIndex`": $([string]::join(" ", $arrDiskPartDriveLettersNotOnFirstHardDisk))"
        $iOverallWarningCt++

        # Attempt to map affected drive letters to last available drive letter
        foreach ($strDiskPartDriveLettersNotOnFirstHardDisk in $arrDiskPartDriveLettersNotOnFirstHardDisk)
        {
            # Check if at least one drive letter available
            $iDriveLettersNotInUseCt = $lstDriveLettersNotInUse.Count
            if ($iDriveLettersNotInUseCt -gt 0)
            {
                # Available
                $strNextDriveLetterNotInUse = $lstDriveLettersNotInUse[0]    # Select first element
                $lstDriveLettersNotInUse.RemoveAt(0)                         # Remove first element

                # Update string to re-map drive letters in DiskPart format script
                $strDiskPartFormatDriveLetterRemappings += "select volume `"$strDiskPartDriveLettersNotOnFirstHardDisk`"`r`nassign letter=`"$strNextDriveLetterNotInUse`"`r`n"

                write-host "$((get-date).tostring()): Updating DiskPart format script to re-map drive letter `"$strDiskPartDriveLettersNotOnFirstHardDisk`" to `"$strNextDriveLetterNotInUse`""
                write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Updating DiskPart format script to re-map drive letter `"$strDiskPartDriveLettersNotOnFirstHardDisk`" to `"$strNextDriveLetterNotInUse`""
            }
            else
            {
                # Not available
                write-host "$((get-date).tostring()): ERROR: No drive letters available to re-map drive letter `"$strDiskPartDriveLettersNotOnFirstHardDisk`"" -ForegroundColor Red
                write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: No drive letters available to re-map drive letter `"$strDiskPartDriveLettersNotOnFirstHardDisk`""
                $iOverallErrorCt++
            }
        }
    }


    #----------------------------------------------#
    # Get the original type of the first hard disk #
    #----------------------------------------------#
    # Get DiskPart info
    $objFirstDiskTypeOriginal = GetHardDiskType -DiskPartPath $strDiskPartExe -DiskIndex $iFirstDiskIndex -DiskPartExitCodeLookupHashtable $htDiskPartExitCodeLookup

    # Get the DiskPart result
    $iDiskPartExitCodeOriginal = $objFirstDiskTypeOriginal.DiskPartExitCode
    if ($iDiskPartExitCodeOriginal -eq 0)
    {
        write-host "$((get-date).tostring()): DiskPart List Disk (1) exit code: $iDiskPartExitCodeOriginal [$($objFirstDiskTypeOriginal.DiskPartExitCodeDesc)]"
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): DiskPart List Disk (1) exit code: $iDiskPartExitCodeOriginal [$($objFirstDiskTypeOriginal.DiskPartExitCodeDesc)]"
    }
    else
    {
        write-host "$((get-date).tostring()): ERROR: DiskPart List Disk (1) exit code: $iDiskPartExitCodeOriginal [$($objFirstDiskTypeOriginal.DiskPartExitCodeDesc)]" -ForegroundColor Red
        write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: DiskPart List Disk (1) exit code: $iDiskPartExitCodeOriginal [$($objFirstDiskTypeOriginal.DiskPartExitCodeDesc)]"
        $iOverallErrorCt++
    }

    # Get the first hard disk original type
    $strDiskTypeOriginal = $objFirstDiskTypeOriginal.DiskType

    if ($strDiskTypeOriginal -ne $null -and ($strDiskTypeOriginal -ieq "GPT" -or $strDiskTypeOriginal -ieq "MBR"))
    {
        write-host "$((get-date).tostring()): `"Disk $iFirstDiskIndex`" original type: $strDiskTypeOriginal"
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): `"Disk $iFirstDiskIndex`" original type: $strDiskTypeOriginal"
    }
    else
    {
        write-host "$((get-date).tostring()): ERROR: `"Disk $iFirstDiskIndex`" original type: $strDiskTypeOriginal" -ForegroundColor Red
        write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: `"Disk $iFirstDiskIndex`" original type: $strDiskTypeOriginal"
        $iOverallErrorCt++
    }


    #-------------------------------------#
    # Check if block files are accessible #
    #-------------------------------------#
    $bAnyBlockFileFound = $false  # Default to no files found

    foreach ($strBlockFile in $BlockFiles)
    {
        if ((TestPathQuiet -DirOrFile $strBlockFile) -eq $true)
        {
            # File found
            write-host "$((get-date).tostring()): BlockFile found: $strBlockFile"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): BlockFile found: $strBlockFile"
            $bAnyBlockFileFound = $true
        }
        else
        {
            # File not found
            write-host "$((get-date).tostring()): BlockFile not found: $strBlockFile"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): BlockFile not found: $strBlockFile"
        }
    }

    # Log if BlockFiles were found
    if ($bAnyBlockFileFound -eq $true)
    {
        write-host "$((get-date).tostring()): One or more `"BlockFiles`" were found"
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): One or more `"BlockFiles`" were found"
    }
    else
    {
        write-host "$((get-date).tostring()): No `"BlockFiles`" were found"
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): No `"BlockFiles`" were found, proceeding"
    }


    #--------------------------------------------------------------------------------------------------------------------------------#
    # Format the disk if -ForceFormat specified OR if the original disk type not already set OR if the block files aren't accessible #
    #--------------------------------------------------------------------------------------------------------------------------------#
    if ($ForceFormat -eq $true -or $strDiskTypeOriginal -ine $BootDiskType -or $bAnyBlockFileFound -eq $false)
    {
        write-host "$((get-date).tostring()): Formatting `"Disk $iFirstDiskIndex`""
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Formatting `"Disk $iFirstDiskIndex`""

        # Create DiskPart text file to format the disk
        $strDiskPartFormatDiskFile = "$env:TEMP\DiskPart_FormatDisk.txt"
        $strDiskPartFormatContent = $strDiskPartFormatDriveLetterRemappings + "select disk $iFirstDiskIndex`r`n" + $strDiskPartFormatContent       # Prepend the drive letter re-mappings plus the first hard disk index
        $strDiskPartFormatContent | Out-File $strDiskPartFormatDiskFile -Encoding ascii -Force

        # Execute DiskPart.exe to format the disk
        $objDiskPartRslt = Execute-Command -commandTitle "DiskPart" -commandPath $strDiskPartExe -commandArguments "/s $strDiskPartFormatDiskFile"
        $arrDiskPartOutput = $objDiskPartRslt.stdout -split "`r`n"   # Need to split stdout into an array since it's just a string
        $iDiskPartExitCode = $objDiskPartRslt.ExitCode
    
        # Resolve the DiskPart exit code to a description
        $strDiskPartExitCodeDesc = $htDiskPartExitCodeLookup.$iDiskPartExitCode

        if ($strDiskPartExitCodeDesc -eq $null -or $strDiskPartExitCodeDesc.trim() -eq "")
        {
            $strDiskPartExitCodeDesc = "Unknown"
        }

        # Get the DiskPart result
        if ($iDiskPartExitCode -eq 0)
        {
            write-host "$((get-date).tostring()): DiskPart Format Disk exit code: $iDiskPartExitCode [$strDiskPartExitCodeDesc]"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): DiskPart Format Disk exit code: $iDiskPartExitCode [$strDiskPartExitCodeDesc]"
        }
        else
        {
            write-host "$((get-date).tostring()): ERROR: DiskPart Format Disk exit code: $iDiskPartExitCode [$strDiskPartExitCodeDesc]" -ForegroundColor Red
            write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: DiskPart Format Disk exit code: $iDiskPartExitCode [$strDiskPartExitCodeDesc]"
            $iOverallErrorCt++
        }


        #---------------------------------------------#
        # Get the updated type of the first hard disk #
        #---------------------------------------------#
        # Get DiskPart info
        $objFirstDiskTypeUpdated = GetHardDiskType -DiskPartPath $strDiskPartExe -DiskIndex $iFirstDiskIndex -DiskPartExitCodeLookupHashtable $htDiskPartExitCodeLookup

        # Get the DiskPart result
        $iDiskPartExitCodeUpdated = $objFirstDiskTypeUpdated.DiskPartExitCode
        if ($iDiskPartExitCodeUpdated -eq 0)
        {
            write-host "$((get-date).tostring()): DiskPart List Disk (2) exit code: $iDiskPartExitCodeUpdated [$($objFirstDiskTypeUpdated.DiskPartExitCodeDesc)]"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): DiskPart List Disk (2) exit code: $iDiskPartExitCodeUpdated [$($objFirstDiskTypeUpdated.DiskPartExitCodeDesc)]"
        }
        else
        {
            write-host "$((get-date).tostring()): ERROR: DiskPart List Disk (2) exit code: $iDiskPartExitCodeUpdated [$($objFirstDiskTypeUpdated.DiskPartExitCodeDesc)]" -ForegroundColor Red
            write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: DiskPart List Disk (2) exit code: $iDiskPartExitCodeUpdated [$($objFirstDiskTypeUpdated.DiskPartExitCodeDesc)]"
            $iOverallErrorCt++
        }

        # Get the first hard disk updated type
        $strDiskTypeUpdated = $objFirstDiskTypeUpdated.DiskType

        if ($strDiskTypeUpdated -ne $null -and $strDiskTypeUpdated -ieq $BootDiskType)
        {
            write-host "$((get-date).tostring()): `"Disk $iFirstDiskIndex`" updated type: $strDiskTypeUpdated"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): `"Disk $iFirstDiskIndex`" updated type: $strDiskTypeUpdated"
        }
        else
        {
            write-host "$((get-date).tostring()): ERROR: `"Disk $iFirstDiskIndex`" updated type: $strDiskTypeUpdated" -ForegroundColor Red
            write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: `"Disk $iFirstDiskIndex`" updated type: $strDiskTypeUpdated"
            $iOverallErrorCt++
        }


        #-----------------------------------------------------------------------------------------------------#
        # Make sure the first hard disk drive letters match the original DiskPart format script drive letters #
        #-----------------------------------------------------------------------------------------------------#
        # Get all disks with respective partitions and volumes after the format
        $arrobjDiskPartVolMapping2 = GetDiskPartitionVolumeMappings
        $arrFirstDiskVolumes2 = @($arrobjDiskPartVolMapping2 | where {$_.DiskIndex -eq $iFirstDiskIndex} | select -ExpandProperty VolumeName | sort)
        
        # Convert arrays to strings for comparison
        $strFirstDiskVolumes2 = [string]::join(" ", ($arrFirstDiskVolumes2 | sort -Unique)).toupper().trim()
        $strDriveLettersInDiskPartScript = [string]::join(" ", ($arrDriveLettersInDiskPartScript | sort -Unique)).toupper().trim()

        # Compare strings, which should be identical if DiskPart format script executed properly
        if ($strFirstDiskVolumes2 -ieq $strDriveLettersInDiskPartScript)
        {
            write-host "$((get-date).tostring()): `"Disk $iFirstDiskIndex`" volumes match DiskPart format disk script: $strFirstDiskVolumes2"
            write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): `"Disk $iFirstDiskIndex`" volumes match DiskPart format disk script: $strFirstDiskVolumes2"
        }
        else
        {
            write-host "$((get-date).tostring()): ERROR: `"Disk $iFirstDiskIndex`" volumes don't match DiskPart format disk script: $strFirstDiskVolumes2" -ForegroundColor Red
            write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: `"Disk $iFirstDiskIndex`" volumes don't match DiskPart format disk script: $strFirstDiskVolumes2"
            $iOverallErrorCt++
        }


        #----------------------------------------------------#
        # Verify no files exist on C: since it was formatted #
        #----------------------------------------------------#
        $strFirstDiskVolumePath = "C:"

        if ((TestPathQuiet -DirOrFile $strFirstDiskVolumePath) -eq $true)
        {
            # C: found, check if any folders or files exist, to verify disk was formatted
            $iFirstDiskVolFileCt = @(gci $strFirstDiskVolumePath -Force).Count

            if ($iFirstDiskVolFileCt -eq 0)
            {
                # No folders/files
                write-host "$((get-date).tostring()): $iFirstDiskVolFileCt Folders/Files found directly in $strFirstDiskVolumePath"
                write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): $iFirstDiskVolFileCt Folders/Files found directly in $strFirstDiskVolumePath"
            }
            else
            {
                # One or more folders/files
                write-host "$((get-date).tostring()): ERROR: $iFirstDiskVolFileCt Folders/Files still found directly in $strFirstDiskVolumePath" -ForegroundColor Red
                write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: $iFirstDiskVolFileCt Folders/Files still found directly in $strFirstDiskVolumePath"
                $iOverallErrorCt++
            }
        }
        else
        {
            # C: not found
            write-host "$((get-date).tostring()): ERROR: $strFirstDiskVolumePath not found" -ForegroundColor Red
            write-log -FilePath $strLogfile -Type Error -Message "$($strGuidPrefix): ERROR: $strFirstDiskVolumePath not found"
            $iOverallErrorCt++
        }
    }
    else
    {
        write-host "$((get-date).tostring()): Skipping format of `"Disk $iFirstDiskIndex`""
        write-log -FilePath $strLogfile -Type Informational -Message "$($strGuidPrefix): Skipping format of `"Disk $iFirstDiskIndex`""
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
