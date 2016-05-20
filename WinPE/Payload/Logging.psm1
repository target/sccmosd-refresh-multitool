#region logging
function Write-Log
{
  <#
    .Synopsis
      Write a message to a log file in a format compatible with Trace32 and Config Manager logs.
    .Description
      This cmdlet takes a given message and formats that message such that it's compatible with
      the cmtrace log viewer tool used for reading/parsing System Center log files. Several iteme
      are determiend when the function is called:
        - The date and time (to the millisecond)
        - The component is the name of the parent function that calls write-log. If it's not part
            of a function then it's blank
        - File is the name:line of the script that called Write-Log
    .Parameter Message
      The actual message to be logged.
    .Parameter FilePath
      The path to the log file to be generated/written to. By default this cmdlet will wite to 
      %TEMP%\scriptname.ps1.MMddyyyy.log. Alternatively a path to a file may be provided.
    .Parameter Type
      The type of event being logged. Valid values are 1, 2 and 3. Each number corresponds to a 
      message type:
        Informational (default)
        Warning
        Error
  #>
  [CmdletBinding()]
  param(
    [Parameter( Mandatory = $true )]
    [string] $Message,
    [ValidateSet("Informational","Warning","Error")] 
    [string] $Type="Informational",
    [string] $FilePath="$($env:TEMP)\$(Split-Path -Leaf $PSCommandPath)_$(get-date -format `"MMddyyyy`").log"
  )
  
  begin
  {
    $TZBias = (Get-WmiObject -Query "Select Bias from Win32_TimeZone").bias
    $Stack = Get-PSCallStack
    $Component = $Stack[1].Command
    $File = ($Stack[1].Location).Replace(' line ','')
    $Thread = 0
    switch ($Type)
    {
        "Informational" {$Level = 1}
        "Warning"       {$Level = 2}
        "Error"         {$Level = 3}
    }
  }
  
  process
  {
    $Time = Get-Date -Format "HH:mm:ss.ffffff"
    $Date = Get-Date -Format "MM-dd-yyyy"

    $Output  = "<![LOG[$($Message)]LOG]!><time=`"$($Time)`" date=`"$($Date)`" "
    $Output += "component=`"$($Component)`" context=`"$($Context)`" type=`"$($Level)`" "
    $Output += "thread=`"$($Thread)`" file=`"$($File)`">"
    
    Write-Verbose "$Time $Date`t$Message"
    Out-File -InputObject $Output -Append -NoClobber -Encoding Default -FilePath $FilePath
  }
}
#endregion