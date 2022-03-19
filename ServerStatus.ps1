#if you are having trouble running a script on the server, then you need to run the following command in an Powershell as an admin, and choose 'Y':
#Set-executionpolicy remotesigned


###########################################################################
#                   XMPie Server Status Diagnostics Tool                  #
###########################################################################


###########################################################################
#                                                                         #
#                                                                         #
#  DISCLAIMER                                                             #
#                                                                         #
# The utility is provided on an "AS IS" basis.                            #
#                                                                         #
# XMPie disclaims any and all warranties relating to the utility,         #
# documentation and other files, express or implied, including but not    #
# limited to the implied warranties of non-infringement of third part     #
# right, mechantability and fitness for particular purpose.               #
#                                                                         #
# The utility should not be used or distributed without a written consent #
# from XMPie.                                                             #
#                                                                         #
###########################################################################


#script convertion to EXE file done with:
#https://gallery.technet.microsoft.com/scriptcenter/PS2EXE-GUI-Convert-e7cb69d5
#the actual conversion script can be found at the bottom of this file


#THE param LINE MUST BE THE FIRST LINE OF THE FILE, or else command line parameters will not work
#dealing with command line parameters
#from:
#https://stackoverflow.com/a/2157625
param (
	#which components are we going to check
	#the letters are the same ones from the manual selection in the initial selection menu
	#example: -Components asr
    [string]$Components = "",
	#in the report, put ONLY Errors, Warnings, Etc.
	#example: -ReportLevel ew
    [string]$ReportLevel = "",
	#default days period to check. overrides the set values
	#example: -Days 14
    [int]$Days = "",
	#only write a log file if there is at least 1 error/warning/notice. according to the selection of the user
	#example: -LogConditionLevel ewn
    [string]$LogConditionLevel = "",
	#where should the log file be saved to
	#example: -LogLocation "C:\XMPLogs\ServerStatus"
    [string]$LogLocation = "",
	#create a monitor tool in XMPieDashboard
	[switch]$MonitorCreate = $false,
	#run the script for an XMPieDashboard Monitor Tool
	[switch]$MonitorRun = $false,
	#run the script for a scheduled task
	[switch]$ScheduledTask = $false,
	#the help parameter. works with both -help and -h
	[switch]$h = $false,
	[switch]$help = $false
)


$ScriptVersion = "2021-12-12"
#Let's set a version. why not?

#check PowerShell version (not needed, as we assume a minimum of Windows Server 2012)
#$PS_Version=($PSVersionTable.PSVersion).Major


#if the user entered components as command line parameters, we assume the script should run and close without interaction
if ($Components) {
	[switch]$RunSilent = $true
}
else {
	[switch]$RunSilent = $false
}

#if there is content in the parameter LogLocation, then we remove the trailing slash
if ($LogLocation) {
	$LogLocation = $LogLocation.TrimEnd('\')
}


#Set the console name to whatever we like. why? because it is cool we can do it, I guess
$host.ui.RawUI.WindowTitle = "XMPie Server Status Tests Tool - version $ScriptVersion"
#and also write the version to the shell itself
Write-Output "XMPie Server Status Diagnostics Tool`r`nVersion: $ScriptVersion"


#The standard 'pause' command, so it appears, is not so standard. This function emulates it
# Taken from here:
# https://blogs.technet.microsoft.com/heyscriptingguy/2013/10/01/rebuild-the-pause-command-with-powershell/
Function PauseHere() {
	Param(
		$DisplayMessage=$TRUE,
		$Content="Press any key to continue..."
	)
	If ($DisplayMessage) { Write-Output $Content }
	$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
	$HOST.UI.RawUI.Flushinputbuffer()
}



#checking if the script was exacuted by PowerShell (and then we are running a PS1 file) or something else (and then we are using an EXE version)
$ExecutingCommand = (Get-WmiObject Win32_Process -Filter "ProcessID=$pid").CommandLine
if ($ExecutingCommand.contains("powershell.exe")) {
	$PS1orEXE = "ps1"
}
else {
	$PS1orEXE = "exe"
}


#Find a string inside another string. Only output if the relevant string is indeed there
#Usage:
# $VariableOrFunction | grep "StringToFind"
function grep {
  $input | out-string -stream | select-string $args
}

#
#TODO: REVISE!!!
#
#once we started compiling the ps1 into an EXE file, identifying the click or shell became very problematic
#decision: when running a ps1 file, assume we are in a shell. when an EXE file, then it is a click
#
#Determine if the script is being ran via double-click or from the shell itself
#Returns 'click' if by double-click or 'shell' if from the shell
#When using it in an IF condition, put the name in brackets, like so:
#if ((ShellOrClick) -eq "click")
Function ShellOrClick {
	$commandLine = (Get-WmiObject Win32_Process -Filter "ProcessID=$pid").CommandLine
	$RanByRightClick = $commandLine | grep "&"
	if ($RanByRightClick) {
	# if ($PS1orEXE -eq "exe") {
		return "click"
	}
	else {
		return "shell"
	}
}

$DisclaimerMessageGUI = "DISCLAIMER

The utility is provided on an `"AS IS`" basis.

XMPie disclaims any and all warranties relating to the utility, documentation and other files, expressed or implied, including but not limited to the implied warranties of non-infringement of third part right, mechantability and fitness for particular purpose.

The utility should not be used or distributed without a written consent from XMPie.

Click Yes to accept these conditions."

$DisclaimerMessageText = "###########################################################################
#                                                                         #
#                                                                         #
#  DISCLAIMER                                                             #
#                                                                         #
# The utility is provided on an `"AS IS`" basis.                            #
#                                                                         #
# XMPie disclaims any and all warranties relating to the utility,         #
# documentation and other files, expressed or implied, including but not  #
# limited to the implied warranties of non-infringement of third part     #
# right, mechantability and fitness for particular purpose.               #
#                                                                         #
# The utility should not be used or distributed without a written consent #
# from XMPie.                                                             #
#                                                                         #
###########################################################################"

Write-Output $DisclaimerMessageText

#Ask for administrator permissions (needed at least for services and IIS restart)
#the EXE version always runs as an admin, so this is not needed in such a case
if ((($PS1orEXE -eq "ps1") -or ((ShellOrClick) -eq "shell")) -and (!$MonitorRun) -and (!$ScheduledTask)){
	If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
		$arguments = "& '" + $myinvocation.mycommand.definition + "'"
		Start-Process powershell -Verb runAs -ArgumentList $arguments
		Break
	}
}

#if -h or -help were passed as parameters, then show a short help to the perplexed user and exit
$HelpText = "
NAME
    ServerStatus-DATE.ps1
`r`n
SYNOPSIS
    Runs diagnostics and status checks on XMPie servers
`r`n
SYNTAX
    ServerStatus-DATE.ps1 [[-Components] <String>] [[-Days] <Integer>] [[-ReportLevel] <String>] [[-LogLocation] <String>] [[-LogConditionLevel] <String>]
`r`n
`r`n
    Examples:
    ServerStatus-DATE.ps1 -Components asr
    Run the server without interaction, and assume only a director with an SQL server and uStore using SQL Windows authentication (because we specify components)
`r`n
    ServerStatus-DATE.ps1 -Components asr -ReportLevel dew
    Same as above, but only write to the log details, errors and warnings
`r`n
    ServerStatus-DATE.ps1 -Components asr -ReportLevel dew -LogLocation `"C:\XMPLogs\ServerStatus`" -LogConditionLevel ew
    Same as above, and write the log to a specific location, and only if there are errors and/or warnings
`r`n
    ServerStatus-DATE.ps1 -help
    ServerStatus-DATE.ps1 -h
    Show this help and exit
`r`n
DESCRIPTION
    -- ServerStatus is a script that is meant for the use of XMPie Staff only --
    This script can run both in interactive and non-interactive modes, and can be ran as a scheduled task.
`r`n
PARAMETERS
    -Components <String>
	    Run checks for specified selected components.
        Causes the script to run non-interactively.
		Assume Windows authentication for SQL queries.
        Good for scheduled tasks.

        Available letters as components:
        Z - Run all tests
		W - Try connecting to the DBs using Windows authentication
        A - Any type of Director solo or other
        D - Director without production
        S - SQL server
        R - uStore
        T - Extension server
        X - Xlim production
        I - InDesign production
        E - Email production
        G - uImage production
        C - Circle Agent
        L - XMPL Server
        M - Marketing Console services or web site
		F - FreeFlow Core

	-Days <Integer>
		Default days period to check. Dverrides whatever values that are already set

    -ReportLevel <String>
        Cause the script to save in the report only the selected levels.
        By default the report includes all levels.

        Available levels:
        H - header. Some general details and amount of errors, warnings and notices found
        D - details. Details about the server (name, IP, Etc.)
        E - errors
        W - warnings
		N - notice
        I - some collected information that may be of interest
        G - general results of all the tests that resulted without an error/warning

    -LogLocation <String>
	    Save all logs in a specified folder.
        Creates the folder if it does not exist.
        By default, the log file is saved where the script is running from.

    -LogConditionLevel <String>
        Defines if a log file will be created at all, according to the existence of errors/warnings.
        By default, a log file will always be created.

        Available levels:
        E - errors
        W - warnings
		N - notices
		I - Information (meaning that there will always be a log file created)

	-MonitorCreate <String>
		Must run with the option -Components
		Creates a XMPieDashboard Monitor Tool that produces a daily report. A Windows Scheduled Task is created, and it runs the ServerStatus script daily, and saves the report to:
		X:\XMPie\XMPieDashboard\Monitoring\ServerStatus.txt

	-MonitorRun
		Assumes that the script was already executed with the option -MonitorCreate
		An internal option that is used when running the script for the XMPieDashboard Monitor Tools

	-ScheduledTask
		An internal option that is used when running the script for a scheduled task

	-h
    -help
    Show this help text and exit.
"

if (($h) -or ($help)) {
	Write-Output $HelpText
	if ((ShellOrClick) -eq "click" -and (!$RunSilent)) {
		PauseHere -Content "Press any key to continue..."
	}
	exit
}





####################################################
#  initializing
####################################################

#counting errors, warnings and notices as we go, in order to give a summary at the end
#this is a very nice idea introduced by Roger Pineda of the Honduras team
$ErrorCount = 0
$WarningCount = 0
$NoticeCount = 0

#error messages that may be due to the fact that we are running all tests, using the Z component
$ErrorMessagesCombined = ""

#the following regular expression checks if there is anything EXCEPT alphanumeric characters and dots
$IPURLValidation = "[^a-zA-Z0-9\.\-]"

#Get the computer name
$Machine = $env:computername

#Current domain
$Domain = $env:USERDOMAIN

#Current user
$RunningUser = $env:USERNAME

#Set the timestamp for the entire script to use
$RunTime=get-date -f yyyy-MM-dd_HH-mm-ss

#Get the location of the script (where it is running from)
if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") {
	$ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
}
else {
	$ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0])
    if (!$ScriptPath){
		$ScriptPath = "."
	}
}
# $LocationFull = (Get-Variable MyInvocation).Value
$ScriptFileName = $MyInvocation.MyCommand.Name
#$ScriptPath = Split-Path $LocationFull.MyCommand.Path
$ConfFileFullPath = "$ScriptPath\ServerStatus.conf"
if (Test-Path -Path $ConfFileFullPath) {
	$ConfigFileExists = "Yes"
}
else {
	$ConfigFileExists = "No"
}



#These details above will give us the prefix for the folder and all files
$File_Prefix = "ServerReport-$Machine-$RunTime"

#Create all needed files, with the timestamp, in a folder
#  Everything: every output should go there, no matter the result
#  Error, Warnings, Notices and Info will take the relevant output, only if it is an exception
#  General shows details that are collected, but are not worth special mention
#  Details will have the server details
#  The Report is the compiled report, including the collected info, exceptions, and then all collected info
$ScriptFiles=@('Error','Warning','Notice','Info','General','Everything','Details','FULL')
#if the user passed a parameter for the log files location - we will respect that
if (!$LogLocation) {
	$LogsFolder="$ScriptPath\$File_Prefix"
}
else {
	$LogsFolder="$LogLocation\$File_Prefix"
	#since it is a custom log location, we need to create it if it does not exist
	$LogLocationExists = Test-Path -Path $LogLocation
	if ($LogLocationExists -eq $False) {
		Write-Host "Custom log location $LogLocation does not exist, so it is being created"
		New-Item -ItemType directory $LogLocation -Force
	}
}

Write-Output ""
New-Item $LogsFolder -ItemType directory -Force > $null
foreach ($TheFile in $ScriptFiles) {
   New-Item $LogsFolder\$File_Prefix-$TheFile.txt -ItemType file > $null
   $FileName=$TheFile
   $FileVar="File_$TheFile"
   New-Variable -Name "File_$TheFile" -Value "$File_Prefix-$FileName.txt"
   ${FileVar}="ServerReport-" + $Machine + $RunTime + "-" + $FileName +".txt"
   # Write-Output File var is $FileVar
}


#UTF8 character codes can be found here:
#https://www.w3schools.com/charsets/ref_utf_block.asp
$LineSeparating = "#" * 52
$LineSeparatingError = (([char]9608).ToString() * 20) + "`r`n" + ([char]9608).ToString() + "      ERRORS      " + ([char]9608).ToString() + "`r`n" + (([char]9608).ToString() * 20) 
# $LineSeparatingWarning = ([char]9608).ToString() * 20
$LineSeparatingWarning = (([char]9608).ToString() * 20) + "`r`n" + ([char]9608).ToString() + "     WARNINGS     " + ([char]9608).ToString() + "`r`n" + (([char]9608).ToString() * 20) 
# $LineSeparatingNotice = ([char]9608).ToString() * 20
$LineSeparatingNotice = (([char]9608).ToString() * 20) + "`r`n" + ([char]9608).ToString() + "     NOTICES      " + ([char]9608).ToString() + "`r`n" + (([char]9608).ToString() * 20) 
# $LineSeparating  = ([char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608)
#LineSeparating  = "***************************************************************************************************"


#Write To File
#this is the main logging function
#take output, and write to the appropriate log file
Function wtf() {
	Param(
		[string]$Item = "",
		[string]$Contents = "",
		[string]$ShortLevel = "d",
		[string]$Addition = ""
	)
	#we have different logging levels:
	switch ($ShortLevel) {
		e {$Level = "Error"}
		w {$Level = "Warning"}
		n {$Level = "Notice"}
		i {$Level = "Info"}
		g {$Level = "General"}
		d {$Level = "Details"}
		#defaulting to general
		default {$Level = "General"}
	}
	# Write the output to the relevant log file
	#if we want a separator, then here it is defined:
	# $separatorWTF = ([char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608+[char]9608)
	# if it is a general comment or collected details, then put to general. we assume no 'problematic' behavior for these messages
	if ($Level -eq "General" -Or $Level -eq "Details") {
		if ($Contents) {
			Write-Output "`r`n$Item" $Contents | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-$Level.txt
			Write-Output "`r`n$Item" $Contents | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-Everything.txt
		}
		else {
			Write-Output "`r`n$Item" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-$Level.txt
			Write-Output "`r`n$Item" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-Everything.txt
		}
	}
	# if it is not a general comment, then we check if there is a problem or not
	else {
		#optional: add something before showing the message contents
		#if ($Contents) {
		#check if there is anything in the contents, and if so, add the 'result' to it
		#$ContentsResult= Write-Output "result: " $Contents
		$LevelBraces = ([char]9608).ToString() + " " + $Level + " " + ([char]9608).ToString()
		$ContentsResult = Write-Output $Contents
		$AdditionResult = ""
		if ($Addition) {
			$AdditionContents = "-" + ([char]9658).ToString() + " Additional Details " + ([char]9668).ToString() + "-`r`n" + $Addition
			$AdditionResult = Write-Output $AdditionContents
		}
		Write-Output "`r`n$LevelBraces`r`n$Item" $ContentsResult $AdditionResult | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-$Level.txt
		Write-Output "`r`n$LevelBraces`r`n$Item" $ContentsResult $AdditionResult | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-Everything.txt
		#}
	}
}

#wtf "IIS services" "Nope. Nothing here..." w "No need to do anything"


Function LogTitle2 () {
	param(
		[string] $TitleText = ""
	)
	$TitleTextFormatted = "--" + ([char]9658).ToString() + " $TitleText " + ([char]9668).ToString() + "--"
	return $TitleTextFormatted
}


# a function to search the system registry
# https://gallery.technet.microsoft.com/scriptcenter/Search-Registry-Find-Keys-b4ce08b4
function Search-Registry { 
<# 
.SYNOPSIS 
Searches registry key names, value names, and value data (limited). 
 
.DESCRIPTION 
This function can search registry key names, value names, and value data (in a limited fashion). It outputs custom objects that contain the key and the first match type (KeyName, ValueName, or ValueData). 
 
.EXAMPLE 
Search-Registry -Path HKLM:\SYSTEM\CurrentControlSet\Services\* -SearchRegex "svchost" -ValueData 
 
.EXAMPLE 
Search-Registry -Path HKLM:\SOFTWARE\Microsoft -Recurse -ValueNameRegex "ValueName1|ValueName2" -ValueDataRegex "ValueData" -KeyNameRegex "KeyNameToFind1|KeyNameToFind2" 
 
#> 
    [CmdletBinding()] 
    param( 
        [Parameter(Mandatory, Position=0, ValueFromPipelineByPropertyName)] 
        [Alias("PsPath")] 
        # Registry path to search 
        [string[]] $Path, 
        # Specifies whether or not all subkeys should also be searched 
        [switch] $Recurse, 
        [Parameter(ParameterSetName="SingleSearchString", Mandatory)] 
        # A regular expression that will be checked against key names, value names, and value data (depending on the specified switches) 
        [string] $SearchRegex, 
        [Parameter(ParameterSetName="SingleSearchString")] 
        # When the -SearchRegex parameter is used, this switch means that key names will be tested (if none of the three switches are used, keys will be tested) 
        [switch] $KeyName, 
        [Parameter(ParameterSetName="SingleSearchString")] 
        # When the -SearchRegex parameter is used, this switch means that the value names will be tested (if none of the three switches are used, value names will be tested) 
        [switch] $ValueName, 
        [Parameter(ParameterSetName="SingleSearchString")] 
        # When the -SearchRegex parameter is used, this switch means that the value data will be tested (if none of the three switches are used, value data will be tested) 
        [switch] $ValueData, 
        [Parameter(ParameterSetName="MultipleSearchStrings")] 
        # Specifies a regex that will be checked against key names only 
        [string] $KeyNameRegex, 
        [Parameter(ParameterSetName="MultipleSearchStrings")] 
        # Specifies a regex that will be checked against value names only 
        [string] $ValueNameRegex, 
        [Parameter(ParameterSetName="MultipleSearchStrings")] 
        # Specifies a regex that will be checked against value data only 
        [string] $ValueDataRegex 
    ) 
 
    begin { 
        switch ($PSCmdlet.ParameterSetName) { 
            SingleSearchString { 
                $NoSwitchesSpecified = -not ($PSBoundParameters.ContainsKey("KeyName") -or $PSBoundParameters.ContainsKey("ValueName") -or $PSBoundParameters.ContainsKey("ValueData")) 
                if ($KeyName -or $NoSwitchesSpecified) { $KeyNameRegex = $SearchRegex } 
                if ($ValueName -or $NoSwitchesSpecified) { $ValueNameRegex = $SearchRegex } 
                if ($ValueData -or $NoSwitchesSpecified) { $ValueDataRegex = $SearchRegex } 
            } 
            MultipleSearchStrings { 
                # No extra work needed 
            } 
        } 
    } 
 
    process { 
        foreach ($CurrentPath in $Path) { 
            Get-ChildItem $CurrentPath -Recurse:$Recurse |  
                ForEach-Object { 
                    $Key = $_ 
 
                    if ($KeyNameRegex) {  
                        Write-Verbose ("{0}: Checking KeyNamesRegex" -f $Key.Name)  
         
                        if ($Key.PSChildName -match $KeyNameRegex) {  
                            Write-Verbose "  -> Match found!" 
                            return [PSCustomObject] @{ 
                                Key = $Key 
                                Reason = "KeyName" 
                            } 
                        }  
                    } 
         
                    if ($ValueNameRegex) {  
                        Write-Verbose ("{0}: Checking ValueNamesRegex" -f $Key.Name) 
             
                        if ($Key.GetValueNames() -match $ValueNameRegex) {  
                            Write-Verbose "  -> Match found!" 
                            return [PSCustomObject] @{ 
                                Key = $Key 
                                Reason = "ValueName" 
                            } 
                        }  
                    } 
         
                    if ($ValueDataRegex) {  
                        Write-Verbose ("{0}: Checking ValueDataRegex" -f $Key.Name) 
             
                        if (($Key.GetValueNames() | ForEach-Object { $Key.GetValue($_) }) -match $ValueDataRegex) {  
                            Write-Verbose "  -> Match!" 
                            return [PSCustomObject] @{ 
                                Key = $Key 
                                Reason = "ValueData" 
                            } 
                        } 
                    } 
                } 
        } 
    } 
}



#Get the value of a registry key, without showing any errors
#why no errors? because if there is an error, then it is like getting no key, so we treat it the same
Function RegKey($Path,$Key) {
	return (Get-ItemProperty -Path $Path -Name $Key -ErrorAction SilentlyContinue).$Key
}

###begin known registry keys
##XMPie
# $Reg_XMPie_main_Location="HKLM:\SOFTWARE\Wow6432Node\XMPie"

##uProduce
$Reg_uProduce_Location="HKLM:\SOFTWARE\Wow6432Node\XMPie\XMPie uProduce Server Object\1.00.000"
$Reg_uProduce_Common="HKLM:\SOFTWARE\Wow6432Node\XMPie\Common\1.00.000"
$Reg_uProduce_AppPath="AppPath"
# $Reg_uProduce_Folder_TempOutput="XMPTempOutputFolder"
# $Reg_uProduce_Folder_TempUpload="UploadPath"

$Reg_uProduce_DB_RegLocation="HKLM:\SOFTWARE\Wow6432Node\XMPie\XMPie uProduce Server Object\1.00.000\DBConnectionInfo"
$Reg_uProduce_DB_ServerAndInstance="MainDBServerName"
# $Reg_uProduce_SQL_Auth_Type="SQLAuthTYPE"
#uProduce SQL server and instance. i.e, localhost\xmpie
$uProduceSQL=RegKey $Reg_uProduce_DB_RegLocation $Reg_uProduce_DB_ServerAndInstance
#first, a variable for the path that (for some weird unknown reason) contains the XMPieExec in it
$XMPiePath=RegKey $Reg_uProduce_Location $Reg_uProduce_AppPath
#now, let's remove the XMPieExec from the path that we get from the registry
$XMPiePathBasic = $XMPiePath -replace "\\XMPieExec\\", ""
#uProduce instance only
# $uProduceSQLSInstanceOnly = ""
if ($uProduceSQL) {
	$uProduceSQLComma = $uProduceSQL.contains(',')
	$uProduceSQLNoServer = $uProduceSQL -replace '^[^\\]*\\', ''
	if ($uProduceSQLComma) {
		$uProduceSQLNoPort = $uProduceSQLNoServer -replace '[^,]*$', ''
		$uProduceSQLSInstanceOnly = $uProduceSQLNoPort -replace ',', ''
	}
	else {
		$uProduceSQLSInstanceOnly = $uProduceSQLNoServer
	}
}


##uStore
$Reg_uStore_Location="HKLM:\SOFTWARE\Wow6432Node\XMPie\XMPie uStore"
# $Reg_uStore_hostname="ServerName"
$Reg_uStore_DB_ServerAndInstance="SQL_CONNECTION(Main Database)_SERVER"
# $Reg_uStore_DB_sa="SQL_CONNECTION(Main Database)_USER"
$Reg_uStore_SharedFolder="uStoreSharedFolder"
# $Reg_uStore_uProduce_Server="uProduceServer"
#unsure what this is. The value was XMPie
# $Reg_uStore_uProduce_Customer="uProduceCustomer"
# $Reg_uStore_uProduce_username="uProduceUserName"
#unsure what is the NETAPI, and is it relevant for our cause
#"NETAPI_USER_ACCOUNT"="xmpie"
#"NETAPI_PASSWORD"="ZRj9wA/rv4oSJfRR9tHUww=="
#unsure what this is
#"DefaultFileSystemLocation"="1"
$uStoreSharedLocation=RegKey $Reg_uStore_Location $Reg_uStore_SharedFolder
#uStore SQL server and instance. i.e, localhost\xmpie
$uStoreSQL=RegKey $Reg_uStore_Location $Reg_uStore_DB_ServerAndInstance
#a possible way to know where uStore is installed, is by looking at the location of the office service
$Reg_uStore_Location_path="HKLM:\SYSTEM\ControlSet001\Services\uStore.OfficeService"
$Reg_uStore_Location_path_key="ImagePath"
$uStorePathService=RegKey $Reg_uStore_Location_path $Reg_uStore_Location_path_key
$uStorePath = $uStorePathService -replace "\\WindowsServices\\OfficeService\\uStore.OfficeService.exe", ""
$uStoreLogPath = "C:\XMPLogs\uStore"
$uStoreLogPathAdmin = "C:\XMPLogs\uStore\AdminApp"
$uStoreLogPathAdminLogFile = "$uStoreLogPathAdmin\uStore.log"
#get uStore instance only
$uStoreSQLSInstanceOnly = ""
if ($uStoreSQL){
	$uStoreSQLComma = $uStoreSQL.contains(',')
	$uStoreSQLNoServer = $uStoreSQL -replace '^[^\\]*\\', ''
	if ($uStoreSQLComma) {
		$uStoreSQLNoPort = $uStoreSQLNoServer -replace '[^,]*$', ''
		$uStoreSQLSInstanceOnly = $uStoreSQLNoPort -replace ',', ''
	}
	else {
		$uStoreSQLSInstanceOnly = $uStoreSQLNoServer
	}
}



##Marketing Console
$Reg_MC_Location="HKLM:\SOFTWARE\Wow6432Node\XMPie\XMPie Marketing Console"
$Reg_MC_DB_Instance="XMPIEDBINSTANCE"
# $Reg_MC_DB_Host="XMPIEDBHOST"
# $Reg_MC_DB_User="XMPIEDBUSER"
# $Reg_MC_uProduce="XMPIEUPRODUCE"
# $Reg_MC_Reporting_Services_URL="XMPIE_RS_INST_URL"
# $Reg_MC_WebServices_URL="XMPIEWSHOST"
$Reg_MC_WebServices_path="XMPIE_INSTALL_WEB_SERVICE"
$Reg_MC_WebSite_path="XMPIE_INSTALL_WEBSITE"
#unsure why there is both a separation of host and instance, and then the following combination
$Reg_MC_DB_ServerAndInstance="XMPIE_DATABASE"
#MC SQL server and instance. i.e, localhost\xmpie
$MCSQL=RegKey $Reg_MC_Location $Reg_MC_DB_ServerAndInstance



#unsure what these are
#"XMPIEMCSERVER_IP"="127.0.0.1"
#"XMPIE_WRITE_BACK_HOST"="127.0.0.1"


#let us set a default SQL instance, according to what we have, for general queries
if ($uProduceSQL) {
	$SQLDefault = $uProduceSQL
}
elseif ($uStoreSQL) {
	$SQLDefault = $uStoreSQL
}
elseif ($MCSQL) {
	$SQLDefault = $MCSQL
}
else {
	$SQLDefault = ""
}


##FreeFlow Core
$Reg_FFC_Location="HKLM:\SOFTWARE\Xerox\FreeFlow\Core\Install"
$Reg_FFC_InstallDir="InstallDir"
# $Reg_FFC_Version="Version"
# $Reg_FFC_Version_Previous="PreviousVersion"
# $Reg_FFC_WorkflowsDir="TenantsHomeRoot"

###end known registry keys



#Get the full list of installed software
#if we want to get the list filtered by, for example, 'indesign'
#we are also looking in the standard non 'Wow6432' section, because non-XMPie software may be located there
#Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -Like '*indesign*'} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize
$Installed_Software_NonFormatted=Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj
$Installed_Software=($Installed_Software_NonFormatted | Format-Table -AutoSize | out-string).Trim()
$Installed_SoftwareNonWow_NonFormatted=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallDateObj
$Installed_SoftwareNonWow=($Installed_SoftwareNonWow_NonFormatted | Format-Table -AutoSize | out-string).Trim()




#before we continue, we need to check if the user chose to create a Monitor Tool.
#if so, then we cannot continue unless some conditions are met.
#"wait!", you say, "why are we not performing these checks already with creating the tool?"
#a good question. we need the query functions, that are only available down the road
if ($MonitorCreate) {
	if (((ShellOrClick) -eq "click" -and (!$RunSilent)) -or ($PS1orEXE -eq "exe")) {
		Write-Output "Creating Monitor Tools is not allowed in non-interactive mode!"
		Write-Output "The script will now exit."
		exit
	}
	#only continue with the process if the Components option was used, because we cannot run a scheduled task without knowing what we are checking
	if (!$Components) {
		Write-Output "Note: you must use the -Components option in order to create a Monitor Tool in XMPieDashboard."
		Write-Output "`r`nFor example:`r`n.\ServerStatus.ps1 -Components asd -MonitorCreate"
		Write-Output "`r`nThe script will now exit."
		Remove-Item -Recurse -Force $LogsFolder
		exit
	}
}



#implementing a GUI menu interface
function Menu_Checkboxes{
	#this function is a result of solutions from multiple resources, but the main one is:
	#http://serverfixes.com/powershell-checkboxes
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    
    # Set the size of your form
    $Form = New-Object System.Windows.Forms.Form
    $Form.width = 700
    $Form.height = 600
    $Form.Text = "Please choose the type of server we are on now"
 
    # Set the font of the text to be used within the form
    $Font = New-Object System.Drawing.Font("Times New Roman",12)
    $Form.Font = $Font
 
    #z-all options
    $OptZ = new-object System.Windows.Forms.checkbox
    $OptZ.Location = new-object System.Drawing.Size(30,10)
    $OptZ.Size = new-object System.Drawing.Size(250,50)
    $OptZ.Text = "Run all tests"
    $OptZ.Checked = $false
    $Form.Controls.Add($OptZ)

	#w-SQL Windows authentication
	$OptW = new-object System.Windows.Forms.checkbox
	$OptW.Location = new-object System.Drawing.Size(30,50)
	$OptW.Size = new-object System.Drawing.Size(500,50)
	$OptW.Text = "Use Windows authentication for Data Base connectiion"
	$OptW.Checked = $false
	$Form.Controls.Add($OptW)

    #a-director
    $OptA = new-object System.Windows.Forms.checkbox
    $OptA.Location = new-object System.Drawing.Size(30,110)
    $OptA.Size = new-object System.Drawing.Size(270,50)
    $OptA.Text = "Any type of Director (solo or other)"
    $OptA.Checked = $false
    $Form.Controls.Add($OptA)

    #d-director without production
    $OptD = new-object System.Windows.Forms.checkbox
    $OptD.Location = new-object System.Drawing.Size(30,150)
    $OptD.Size = new-object System.Drawing.Size(250,50)
    $OptD.Text = "Director without production"
    $OptD.Checked = $false
    $Form.Controls.Add($OptD)

	#s-SQL server
	$OptS = new-object System.Windows.Forms.checkbox
	$OptS.Location = new-object System.Drawing.Size(30,190)
	$OptS.Size = new-object System.Drawing.Size(250,50)
	$OptS.Text = "SQL server"
	$OptS.Checked = $false
	$Form.Controls.Add($OptS)

	#r-uStore
	$OptR = new-object System.Windows.Forms.checkbox
	$OptR.Location = new-object System.Drawing.Size(30,230)
	$OptR.Size = new-object System.Drawing.Size(100,50)
	$OptR.Text = "uStore"
	$OptR.Checked = $false
	$Form.Controls.Add($OptR)

	#f-FFC
	$OptF = new-object System.Windows.Forms.checkbox
	$OptF.Location = new-object System.Drawing.Size(150,230)
	$OptF.Size = new-object System.Drawing.Size(250,50)
	$OptF.Text = "FreeFlow Core"
	$OptF.Checked = $false
	$Form.Controls.Add($OptF)

	#t-extension
	$OptT = new-object System.Windows.Forms.checkbox
	$OptT.Location = new-object System.Drawing.Size(30,270)
	$OptT.Size = new-object System.Drawing.Size(250,50)
	$OptT.Text = "Extension server"
	$OptT.Checked = $false
	$Form.Controls.Add($OptT)

	#x-XLIM
	$OptX = new-object System.Windows.Forms.checkbox
	$OptX.Location = new-object System.Drawing.Size(30,310)
	$OptX.Size = new-object System.Drawing.Size(110,60)
	$OptX.Text = "Xlim production"
	$OptX.Checked = $false
	$Form.Controls.Add($OptX)

	#i-InDesign
	$OptI = new-object System.Windows.Forms.checkbox
	$OptI.Location = new-object System.Drawing.Size(150,310)
	$OptI.Size = new-object System.Drawing.Size(100,60)
	$OptI.Text = "InDesign production"
	$OptI.Checked = $false
	$Form.Controls.Add($OptI)

	#e-Email
	$OptE = new-object System.Windows.Forms.checkbox
	$OptE.Location = new-object System.Drawing.Size(260,310)
	$OptE.Size = new-object System.Drawing.Size(110,60)
	$OptE.Text = "Email production"
	$OptE.Checked = $false
	$Form.Controls.Add($OptE)

	#g-uImage
	$OptG = new-object System.Windows.Forms.checkbox
	$OptG.Location = new-object System.Drawing.Size(370,310)
	$OptG.Size = new-object System.Drawing.Size(110,60)
	$OptG.Text = "uImage production"
	$OptG.Checked = $false
	$Form.Controls.Add($OptG)

	#c-Circle Agent
	$OptC = new-object System.Windows.Forms.checkbox
	$OptC.Location = new-object System.Drawing.Size(30,360)
	$OptC.Size = new-object System.Drawing.Size(110,50)
	$OptC.Text = "Circle Agent"
	$OptC.Checked = $false
	$Form.Controls.Add($OptC)

	#l-XMPL Server
	$OptL = new-object System.Windows.Forms.checkbox
	$OptL.Location = new-object System.Drawing.Size(150,360)
	$OptL.Size = new-object System.Drawing.Size(250,50)
	$OptL.Text = "XMPL Server"
	$OptL.Checked = $false
	$Form.Controls.Add($OptL)

	#m-MC
	$OptM = new-object System.Windows.Forms.checkbox
	$OptM.Location = new-object System.Drawing.Size(30,400)
	$OptM.Size = new-object System.Drawing.Size(300,50)
	$OptM.Text = "Marketing Console services or web site"
	$OptM.Checked = $false
	$Form.Controls.Add($OptM)



    # Add an OK button
    $OKButton = new-object System.Windows.Forms.Button
    $OKButton.Location = new-object System.Drawing.Size(130,500)
    $OKButton.Size = new-object System.Drawing.Size(100,40)
    $OKButton.Text = "OK"
	$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $OKButton.Add_Click({$Form.Close();})
    $form.Controls.Add($OKButton)
 
    #Add a cancel button
    $CancelButton = new-object System.Windows.Forms.Button
    $CancelButton.Location = new-object System.Drawing.Size(255,500)
    $CancelButton.Size = new-object System.Drawing.Size(100,40)
    $CancelButton.Text = "Cancel"
	$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $CancelButton.Add_Click({$Form.Close()})
    $form.Controls.Add($CancelButton)
    
    ###########  This is the important piece ##############
    #                                                     #
    # Do something when the state of the checkbox changes #
    #######################################################
	#in our case, we disable all selections if the user decides to run all tests anyway
    $OptZ.Add_CheckStateChanged({
    $OptA.Enabled = !$OptZ.Checked;
    $OptD.Enabled = !$OptZ.Checked;
    $OptS.Enabled = !$OptZ.Checked;
    $OptR.Enabled = !$OptZ.Checked;
    $OptT.Enabled = !$OptZ.Checked;
    $OptX.Enabled = !$OptZ.Checked;
    $OptI.Enabled = !$OptZ.Checked;
    $OptE.Enabled = !$OptZ.Checked;
    $OptG.Enabled = !$OptZ.Checked;
    $OptC.Enabled = !$OptZ.Checked;
    $OptL.Enabled = !$OptZ.Checked;
    $OptM.Enabled = !$OptZ.Checked;
    $OptF.Enabled = !$OptZ.Checked;
	})
 
    
    # Activate the form
	$Form.AcceptButton = $OKButton
	$Form.CancelButton = $CancelButton
    $Form.Add_Shown({$Form.Activate()})
    $FormResult = $Form.ShowDialog() 

	#decide what to do
	if ($FormResult -eq [System.Windows.Forms.DialogResult]::OK) {
		$FormComponents = ""
		if ($OptZ.Checked) {$FormComponents = $FormComponents + "z"}
		if ($OptW.Checked) {$FormComponents = $FormComponents + "w"}
		if ($OptA.Checked) {$FormComponents = $FormComponents + "a"}
		if ($OptD.Checked) {$FormComponents = $FormComponents + "d"}
		if ($OptS.Checked) {$FormComponents = $FormComponents + "s"}
		if ($OptR.Checked) {$FormComponents = $FormComponents + "r"}
		if ($OptT.Checked) {$FormComponents = $FormComponents + "t"}
		if ($OptX.Checked) {$FormComponents = $FormComponents + "x"}
		if ($OptI.Checked) {$FormComponents = $FormComponents + "i"}
		if ($OptE.Checked) {$FormComponents = $FormComponents + "e"}
		if ($OptG.Checked) {$FormComponents = $FormComponents + "g"}
		if ($OptC.Checked) {$FormComponents = $FormComponents + "c"}
		if ($OptL.Checked) {$FormComponents = $FormComponents + "l"}
		if ($OptM.Checked) {$FormComponents = $FormComponents + "m"}
		if ($OptF.Checked) {$FormComponents = $FormComponents + "f"}
	}
	else {
		Write-Output "You chose to cancel, so we will now exit..."
		exit
	}

	return $FormComponents 
}

function Menu_RunAll{
	#this function is a result of solutions from multiple resources, but the main one is:
	#http://serverfixes.com/powershell-checkboxes
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    
    # Set the size of your form
    $Form = New-Object System.Windows.Forms.Form
    $Form.width = 200
    $Form.height = 240
    $Form.Text = "Server Status Tests"
 
    # Set the font of the text to be used within the form
    $Font = New-Object System.Drawing.Font("Arial",12)
    $Form.Font = $Font
    $FontSmall = New-Object System.Drawing.Font("Arial",8)
    $FontLarge = New-Object System.Drawing.Font("Arial",25)

    # Add a Run button
    $RunButton = new-object System.Windows.Forms.Button
    $RunButton.Location = new-object System.Drawing.Size(40,30)
    $RunButton.Size = new-object System.Drawing.Size(100,40)
    $RunButton.Font = $FontLarge
    $RunButton.Text = "Run"
	$RunButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $RunButton.Add_Click({$Form.Close();})
    $form.Controls.Add($RunButton)
 
    # Add an Options button
    $OptionsButton = new-object System.Windows.Forms.Button
    $OptionsButton.Location = new-object System.Drawing.Size(30,100)
    $OptionsButton.Size = new-object System.Drawing.Size(120,20)
    $OptionsButton.Font = $FontSmall
    $OptionsButton.Text = "Options"
	$OptionsButton.DialogResult = [System.Windows.Forms.DialogResult]::No
    $OptionsButton.Add_Click({$Form.Close();})
    $form.Controls.Add($OptionsButton)
 
    # If there is a configuration file, then add a button to use it
	if ($ConfigFileExists -eq "Yes") {
		$ConfigButton = new-object System.Windows.Forms.Button
		$ConfigButton.Location = new-object System.Drawing.Size(30,130)
		$ConfigButton.Size = new-object System.Drawing.Size(120,20)
		$ConfigButton.Font = $FontSmall
		$ConfigButton.Text = "Use Stored Options"
		$ConfigButton.DialogResult = [System.Windows.Forms.DialogResult]::Ignore
		$ConfigButton.Add_Click({$Form.Close();})
		$form.Controls.Add($ConfigButton)
	}
 
    #Add a cancel button
    $CancelButton = new-object System.Windows.Forms.Button
    $CancelButton.Location = new-object System.Drawing.Size(30,160)
    $CancelButton.Size = new-object System.Drawing.Size(120,20)
    $CancelButton.Font = $FontSmall
    $CancelButton.Text = "Cancel"
	$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $CancelButton.Add_Click({$Form.Close()})
    $form.Controls.Add($CancelButton)
    

    
    # Activate the form
	$Form.AcceptButton = $RunButton
	$Form.AcceptButton = $OptionsButton
	$Form.CancelButton = $CancelButton
    $Form.Add_Shown({$Form.Activate()})
    $FormResult = $Form.ShowDialog() 

	return $FormResult
}

function Menu_Disclaimer{
	#this function is a result of solutions from multiple resources, but the main one is:
	#http://serverfixes.com/powershell-checkboxes
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    
    # Set the size of your form
    $Form = New-Object System.Windows.Forms.Form
    $Form.width = 500
    $Form.height = 450
    $Form.Text = "DISCLAIMER"
 
    # Set the font of the text to be used within the form
    $Font = New-Object System.Drawing.Font("Arial",12)
    $Form.Font = $Font
    # $FontSmall = New-Object System.Drawing.Font("Arial",8)
    # $FontLarge = New-Object System.Drawing.Font("Arial",25)

	#Disclaimer message
	$UserTitle = new-object System.Windows.Forms.Label
	$UserTitle.Location = new-object System.Drawing.Size(30,30)
	$UserTitle.Size = new-object System.Drawing.Size(400,280)
	$UserTitle.Font = $Font
	$UserTitle.Text = "$DisclaimerMessageGUI"
	$Form.Controls.Add($UserTitle)

	# $OptM = new-object System.Windows.Forms.checkbox
	# $OptM.Location = new-object System.Drawing.Size(30,30)
	# $OptM.Size = new-object System.Drawing.Size(400,20)
	# $OptM.Text = $DisclaimerMessageGUI
	# $OptM.Checked = $false
	# $Form.Controls.Add($OptM)
	
    # Add a Yes button
    $RunButton = new-object System.Windows.Forms.Button
    $RunButton.Location = new-object System.Drawing.Size(100,320)
    $RunButton.Size = new-object System.Drawing.Size(100,40)
    $RunButton.Font = $Font
    $RunButton.Text = "Yes"
	$RunButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
    $RunButton.Add_Click({$Form.Close();})
    $form.Controls.Add($RunButton)
 
    # Add a No button
    $CancelButton = new-object System.Windows.Forms.Button
    $CancelButton.Location = new-object System.Drawing.Size(300,320)
    $CancelButton.Size = new-object System.Drawing.Size(100,40)
    $CancelButton.Font = $Font
    $CancelButton.Text = "No"
	$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $CancelButton.Add_Click({$Form.Close()})
    $form.Controls.Add($CancelButton)
     
    # Activate the form
	$Form.AcceptButton = $RunButton
	$Form.CancelButton = $CancelButton
    $Form.Add_Shown({$Form.Activate()})
    $FormResult = $Form.ShowDialog()
	
	#decide what to do
	if ($FormResult -eq [System.Windows.Forms.DialogResult]::Cancel) {
		Write-Output "You chose to cancel, so we will now exit..."
		exit
	}

	#return $FormResult
}

#working with a config file
#relevant only if there are no parameters entered in the shell
#check if there is a .conf file. if there is, then overriding parameters
if ($ConfigFileExists -eq "Yes") {
		#getting parameters and their values from a file
		#from http://tlingenf.spaces.live.com/blog/cns!B1B09F516B5BAEBF!213.entry
		#or from https://serverfault.com/a/891846
		Get-Content "$ConfFileFullPath" | foreach-object -begin {$ConfFile=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("[") -ne $True) -and ($k[0].StartsWith("#") -ne $True)) { $ConfFile.Add($k[0], $k[1]) } }
}

#when compiling the EXE file, the environment is always detected as "shell"
#so a decision was made: when running the EXE file, assume GUI
if ($PS1orEXE -eq "ps1") {
	if ((((ShellOrClick) -eq "shell") -and (!$RunSilent) -and ($ConfigFileExists -eq "Yes"))) {
		#if a configuration file exists, then ask the user if it should be used
		Write-Host "`r`nConfiguration file exists:" -ForegroundColor Red
		Write-Output "$ConfFileFullPath`r`n"
		if ($ConfFile.ConfComponents) {
			Write-Output "Stored component values are:"
			Write-Output $ConfFile.ConfComponents
		}
		
		Write-Output "`r`nDo you want to use the stored settings? (y/n)"
		$UseConfFile = Read-Host
		if ($UseConfFile -match "[yY]") {
			if ($ConfFile.ConfComponents) {$Components = $ConfFile.ConfComponents}
			if ($ConfFile.ConfReportLevel) {$ReportLevel = $ConfFile.ConfReportLevel}
			if ($ConfFile.ConfLogLocation) {$LogLocation = $ConfFile.ConfLogLocation}
			if ($ConfFile.ConfLogConditionLevel) {$LogConditionLevel = $ConfFile.ConfLogConditionLevel}
		}
	}
}
#check if there are any components entered as command line parameters
if ($Components) {
	Write-Host "`r`nThe following components entered as parameters:"
	Write-Host "$Components"
}
else {
	#just in case someone wants to run the command with parameters, let's let them know about it
	Write-Output "`r`nThe script can also be ran in PowerShell with parameters. For more details, run:"
	Write-Output "ServerStatus-$ScriptVersion.ps1 -help`r`n"

#launch the GUI interface
	# if (((ShellOrClick) -eq "click") -and (!$RunSilent) -and (1 -eq 2)) {
	#if we are running an EXE version, then always use the GUI
	#except for cases that we are running a scheduled task ($MonitorRun), because then we call powershell.exe
	
	### 

	# if (($PS1orEXE -eq "exe") -and (!$MonitorRun) -and (!$ScheduledTask)) {
	if ((!$MonitorRun) -and (!$ScheduledTask)) {
		#first, let us show a disclaimer
		Menu_Disclaimer
		#running the first interactive GUI, to determine if we are going to run all tests or not
		$FormRunResult = Menu_RunAll
		if ($FormRunResult -eq "Yes") {
			$Components = "wz"
		}
		elseif ($FormRunResult -eq "No") {
			Write-Output "you chose to not run all tests. Continuing with interactive mode.`r`n"
			#instead of trying to guess what are we supposed to find, we can ask the kind user to give us a general clue
			#don't worry: I am not lazy. I will still perform checks and validations. but it is much easier this way
			$Components = Menu_Checkboxes
		}
		elseif ($FormRunResult -eq "Ignore") {
			Write-Output "you chose to use the existing configuration file.`r`n"
			#instead of trying to guess what are we supposed to find, we can ask the kind user to give us a general clue
			#don't worry: I am not lazy. I will still perform checks and validations. but it is much easier this way
			if ($ConfFile.ConfComponents) {
				$Components = $ConfFile.ConfComponents
			}
		}
		else {
			Write-Output "You chose to cancel, so we will now exit..."
			exit
		}
	}
	else {
		Write-Host "Please choose the type of server we are on now:" -ForegroundColor Green
		Write-Host "(Note that we do not care if it is production, staging, dev or what not)`r`n" -ForegroundColor Gray
		# the original code was referring to a type of server, but it makes much more sense to work according to existing components
		Write-Output ""
		Write-Host "Try to run all tests: " -NoNewLine
		Write-Host "(Z)" -ForegroundColor Yellow
		Write-Host "Try " -NoNewLine
		Write-Host "(W)" -ForegroundColor Yellow -NoNewLine
		Write-Output "indows authentication for SQL connection"
		Write-Host "(A)" -ForegroundColor Yellow -NoNewLine
		Write-Output "ny type of Director (solo or other)"
		Write-Host "(D)" -ForegroundColor Yellow -NoNewLine
		Write-Output "irector without production"
		Write-Host "(S)" -ForegroundColor Yellow -NoNewLine
		Write-Output "QL server"
		Write-Host "uSto" -NoNewLine
		Write-Host "(R)" -ForegroundColor Yellow -NoNewLine
		Write-Output "e"
		Write-Host "Ex" -NoNewLine
		Write-Host "(T)" -ForegroundColor Yellow -NoNewLine
		Write-Output "ension server"
		Write-Host "(X)" -ForegroundColor Yellow -NoNewLine
		Write-Output "lim production"
		Write-Host "(I)" -ForegroundColor Yellow -NoNewLine
		Write-Output "nDesign production"
		Write-Host "(E)" -ForegroundColor Yellow -NoNewLine
		Write-Output "mail production"
		Write-Host "uIma" -NoNewLine
		Write-Host "(G)" -ForegroundColor Yellow -NoNewLine
		Write-Output "e production"
		Write-Host "(C)" -ForegroundColor Yellow -NoNewLine
		Write-Output "ircle Agent"
		Write-Host "XMP" -NoNewLine
		Write-Host "(L)" -ForegroundColor Yellow -NoNewLine
		Write-Output " Server"
		Write-Host "(M)" -ForegroundColor Yellow -NoNewLine
		Write-Output "arketing Console services or web site"
		Write-Host "(F)" -ForegroundColor Yellow -NoNewLine
		Write-Output "reeFlow Core"
		Write-Output ""
		Write-Output "`r`nSelect the components according to the letter in brackets:`r`n"
		$Components = Read-Host
		# Write-Output $Components

	}
		#writing the selected components to a config file
		#and...
		#if a config file does not exist, then one will be created
		#and anyway...
		#not updating the file if we loaded it during the GUI selection
		if ($FormRunResult -ne "Ignore") {
			if ($ConfigFileExists -eq "Yes") {
				#updating conf file only if the options are NOT zw, because these are the default 'Run' components for the GUI
				if (($Components -ne 'wz') -and ($components -ne 'zw')) {
					Write-Output "`r`nUpdating config file with the selected components for the next run:`r`n$Components"
					$ComponentsForConf = "ConfComponents=$Components"
					$USER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name          
					(Get-Content $ConfFileFullPath) | ForEach-Object { $_ -replace "^ConfComponents=.+" , "$ComponentsForConf" } | Set-Content $ConfFileFullPath
					# (Get-Content $ConfFileFullPath) -replace $ComponentsForConf, 'ConfComponents' | Set-Content $ConfFileFullPath
				}
				else {
					Write-Output "`r`nNot updating config file with the default run components (zw)"
				}
			}
			#if there is no configuration file, then we should create one with the selected options
			else {
				Write-Output "Configuration file not found. It will now be created..."
				$ConfFileContents = '#Configuration file for the XMPie Server Status script
#Edit the right side in order to set a value
#For instance, in order to run all tests in SQL Windows authentication, this should be the line:
##ConfComponents=wz
#
#In order to see all available values, run the script with the -help parameter

#The components to be checked
ConfComponents='
				$ConfFileContents = $ConfFileContents + $Components
				$ConfFileContents = $ConfFileContents + '

ConfReportLevel=
ConfLogLocation=
ConfLogConditionLevel='
				#writing a new configuration file if the options are NOT zw, because these are the default 'Run' components for the GUI
				if (($Components -ne 'wz') -and ($components -ne 'zw')) {
					Write-Output "$ConfFileContents" | Out-File -Encoding utf8 $ConfFileFullPath
				}
				Write-Output "Configuration file created"
			}
		}

}

#cheking if the relevant component is a part of the components that we expect to find on this host
#put this 'if' before each section, and check if the relevant components are in the list
#in this example, we will perform an action only if one of the following components was chosen: m s x f
# if ($Components -match "\[\a|m|s|x|f/gi]") {
if ($Components -match "[msxf]") {
	Write-Output ""
}
else { Write-Output ""}

#if the user decided to try and run all checks, then we need to honor his/hers/its decision

if ($Components -match "[z]") {
	if ($Components -match "[w]") {
		$Components = "Zwasrtxiegclmf"
	}
	else {
		$Components = "Zasrtxiegclmf"
	}
}

## SQL connection credentials
#does the kind user have a DB user and pass, or will we need to try Windows authentication?
#uProduce SQL credentials
if ($uProduceSQL) {
	if ($RunSilent -or $Components -match "[w]") {
		$DB_User = ""
		$DB_Password = ""
	}
	else {
		Write-Host ""
		Write-Host "-------------------------------------" -ForegroundColor Black -BackgroundColor White
		Write-Host "-  uProduce SQL user and password   -" -ForegroundColor Black -BackgroundColor White
		Write-Host "-------------------------------------" -ForegroundColor Black -BackgroundColor White
		Write-Host "Enter the DB user name and password. Press Enter in both fields to use Windows authentication" -ForegroundColor Green
		Write-Output "`r`nuProduce DB user name:"
		$DB_User = Read-Host
		Write-Output "`r`nuProduce DB password:"
		$DB_Password = Read-Host -AsSecureString
		$DB_Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DB_Password))
	}
	if ($DB_User -and $DB_Password) {
		#OK! we have user name and password. let's do it!
		$ConnectionString_uProduce = "SQLProcess " + $uProduceSQL + " xmpdb2 " + $DB_User + $DB_Password
	}
	else {
		#oh. no user and password. well... let's see how this goes...
		$ConnectionString_uProduce = "SQLProcess " + $uProduceSQL + ' xmpdb2 -user "" -pass ""'
	}
}

#uStore SQL credentials
if ($Components -match "[r]") {
	if ($RunSilent -or $Components -match "[w]") {
		$DB_User_uStore = ""
		$DB_Password_uStore = ""
	}
	else {
		Write-Host ""
		Write-Host "-----------------------------------" -ForegroundColor Black -BackgroundColor White
		Write-Host "-  uStore SQL user and password   -" -ForegroundColor Black -BackgroundColor White
		Write-Host "-----------------------------------" -ForegroundColor Black -BackgroundColor White
		Write-Host "Enter the DB user name and password. Press Enter in both fields to use Windows authentication" -ForegroundColor Green
		Write-Output "`r`nuStore DB user name:"
		$DB_User_uStore = Read-Host
		Write-Output "`r`nuStore DB password:"
		$DB_Password_uStore = Read-Host -AsSecureString
		$DB_Password_uStore = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DB_Password_uStore))
	}
	if ($DB_User_uStore -and $DB_Password_uStore) {
		#OK! we have user name and password. let's do it!
		$ConnectionString_uStore = "SQLProcess " + $uStoreSQL + " uStore " + $DB_User_uStore + $DB_Password_uStore
	}
	else {
		#oh. no user and password. well... let's see how this goes...
		$ConnectionString_uStore = "SQLProcess " + $uStoreSQL + ' uStore -user "" -pass ""'
	}
}
#Marketing Console SQL credentials - only relevant if we have an instance in the registry
if (($Components -match "[m]") -and ($Reg_MC_DB_Instance)) {
	if ($RunSilent -or $Components -match "[w]") {
		$DB_User_MC = ""
		$DB_Password_MC = ""
	}
	else {
		Write-Host ""
		Write-Host "----------------------------------------------" -ForegroundColor Black -BackgroundColor White
		Write-Host "-  Marketing Console SQL user and password   -" -ForegroundColor Black -BackgroundColor White
		Write-Host "----------------------------------------------" -ForegroundColor Black -BackgroundColor White
		Write-Host "Enter the DB user name and password. Press Enter in both fields to use Windows authentication" -ForegroundColor Green
		Write-Output "`r`nDB user name:"
		$DB_User_MC = Read-Host
		Write-Output "`r`nDB password:"
		$DB_Password_MC = Read-Host -AsSecureString
		$DB_Password_MC = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DB_Password_MC))
	}
	if ($DB_User_MC -and $DB_Password_MC) {
		#OK! we have user name and password. let's do it!
		$ConnectionString_MC = "SQLProcess " + $MCSQL + " XMPDBTRACKING " + $DB_User_MC + $DB_Password_MC
	}
	else {
		#oh. no user and password. well... let's see how this goes...
		$ConnectionString_MC = "SQLProcess " + $MCSQL + ' XMPDBTRACKING -user "" -pass ""'
	}
}
# $SQLLicense = $uProduceSQL + "xmpdb2 -user \"" + $DB_User + "\" -pass \"" + $DB_Password + "\""
# $SQLLicense = "$uProduceSQL xmpdb2 -user '$DB_User' -pass '$DB_Password'"

#run an SQL query to retrieve multiple values / rows
#for SINGLE item values, use the function SQLValue instead
#based on the code from:
#https://stackoverflow.com/a/17991157
#syntax:
#SQLProcess HostAndInstance DBName User Password "Query"
#if user _AND_ password are empty, then use Windows authentication
#Examples:
# SQLProcess  $uProduceSQL xmpdb2 USER PASS "SELECT accountID,accountName FROM [XMPie].[TBL_ACCOUNT]"
# SQLProcess  $uProduceSQL xmpdb2 USER PASS "SELECT accountID,accountName FROM [XMPie].[TBL_ACCOUNT]"
function SQLProcess($server = "", $database = "", $user = "", $pass = "", $sqlText = "", $format = "table")
{
	#if user _AND_ password are empty, then use Windows authentication
    
	if ($user -eq "" -and $pass -eq "") {
		$connection = new-object System.Data.SqlClient.SQLConnection("Data Source=$server;Integrated Security=SSPI;Initial Catalog=$database");
	}
	else {
		$connection = new-object System.Data.SqlClient.SQLConnection("Data Source=$server;Initial Catalog=$database;User ID=$user;Password=$pass;");
	}
    $cmd = new-object System.Data.SqlClient.SqlCommand($sqlText, $connection);

    $connection.Open();
# try/catch was added in order to deal with missing tables
#if it is to be removed, then the if ($reader) condition is irrelevant and should be removed (NOT the entire section. just the condition)
	try {
        $reader = $cmd.ExecuteReader()
    }
    catch {
        Write-Output "An error has occured while trying to perform a query. For the full error, uncomment the line below, in the function SQLProcess"
        #Write-Error -Message "An error has occured. Error Details: $($_.Exception.Message)"
    }

    $ErrorActionPreference = 'Continue'

    if ($reader) {
		$results = @()
		while ($reader.Read())
		{
			$row = @{}
			for ($i = 0; $i -lt $reader.FieldCount; $i++)
			{
				$row[$reader.GetName($i)] = $reader.GetValue($i)
			}
			$results += new-object psobject -property $row            
		}
	}
    $connection.Close();
	
	if ($format -eq "list") {
		$results | Format-List
	}
	elseif ($format -eq "values") {
		$results | Format-Table -HideTableHeaders
	}
	else {
		$results | Format-Table -AutoSize
	}
}

#retrieve a single value from a query
#syntax:
#SQLValue HostAndInstance DBName User Password "Query"
#if user _AND_ password are empty, then use Windows authentication
#Example:
# SQLValue  $uProduceSQL xmpdb2 USER PASS "SELECT [pathValue] FROM [XMPDB2].[XMPie].[TBL_PATH_LOCATOR] WHERE pathName='InternalAddress'"
function SQLValue($server = "", $database = "", $user = "", $pass = "", $sqlText = "")
{
#this function (SQLValue) had problems with user authentication in certain cases
#I took the same functionality that the function SQLProcess had, and the problems were solved
#this is the old code:
	# $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
		# if ($user -eq "" -and $pass -eq "") {
		# $SqlConnection.ConnectionString = "Server=$server;Database=$database;Integrated Security=SSPI"
	# }
	# else {
		# $SqlConnection.ConnectionString = "Server=$server;Database=$database;Integrated Security=SSPI;User ID=$user;Password=$pass;"
	# }

	#and now to the new code. the one that actually works...
	if ($user -eq "" -and $pass -eq "") {
		$SqlConnection = new-object System.Data.SqlClient.SQLConnection("Data Source=$server;Integrated Security=SSPI;Initial Catalog=$database");
	}
	else {
		$SqlConnection = new-object System.Data.SqlClient.SQLConnection("Data Source=$server;Initial Catalog=$database;User ID=$user;Password=$pass;");
	}
	$SqlConnection.Open()
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand
	$SqlCmd.CommandText = $sqlText
	$SqlCmd.Connection = $SqlConnection
	$result = $SqlCmd.ExecuteScalar()
	$SqlConnection.Close()
	return $result
}


#only run a PowerShell cmdlet if it exists in this specific machine
#especially relevant for uImage only machines, since they now (CC2019 and above) run only on desktops
Function CmdletExists () {
	param(
		[string] $CMdlet = ""
	)
	if (Get-Command $CMdlet -errorAction SilentlyContinue -CommandType Cmdlet) {
		return 1
	}
	else {
		return 0
	}
}


#Check if a certain feature is installed
Function FeatureInstalled () {
	Param (
		[string] $Feature = ""
	)
	if (CmdletExists Get-WindowsFeature -eq 1) {
		$Value=Get-WindowsFeature -Name $Feature | Where-Object Installed
		if ($Value) {return 1}
		else {return 0}
	}
	else {
		return "NA"
	}
}

#the function for checking the status of a request to get a URL is from here:
#https://stackoverflow.com/a/44234056
function Get-UrlStatusCode([string] $Url) {
	try {
		(Invoke-WebRequest -Uri $Url -UseBasicParsing -DisableKeepAlive -Method head).StatusCode
	}
	catch [Net.WebException] {
		[int]$_.Exception.Response.StatusCode
	}
}


#check if a local samba / smb network shared folder exists
function LocalShareCheck() {
	param(
		[string] $ShareName = ""
	)
	$ShareExists = Get-SmbShare | Where-Object Name -eq $ShareName
	return $ShareExists
}


#all of the following can only be checked if we have the uProduce SQL instance details
if ($uProduceSQL) {
	#the entire uProduce License table
	$SQLLicense = SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [CDKey],[Type],[Active],[Owner],[ActivationDate] FROM [XMPDB2].[XMPie].[TBL_LICENSE]"
	#is there a 'uStore' item in the License table?
	$SQLLicenseuStore = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [CDKey],[Type],[Active],[Owner],[ActivationDate] FROM [XMPDB2].[XMPie].[TBL_LICENSE] WHERE Type='USTORE'"
	#is there a 'Analytics' item in the License table?
	$SQLLicenseMC = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [CDKey],[Type],[Active],[Owner],[ActivationDate] FROM [XMPDB2].[XMPie].[TBL_LICENSE] WHERE Type='Analytics'"

	#PathLocator table
	# $SQLPathLocator = SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [pathName],[pathValue] FROM [XMPDB2].[XMPie].[TBL_PATH_LOCATOR]"
	#PathLocator Internal address
	$SQLIPInternal = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [pathValue] FROM [XMPDB2].[XMPie].[TBL_PATH_LOCATOR] WHERE pathName='InternalAddress'"
	#PathLocator External address
	$SQLIPExternal = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [pathValue] FROM [XMPDB2].[XMPie].[TBL_PATH_LOCATOR] WHERE pathName='ExternalAddress'"
	#Write-Output "SQLLicense: "$SQLLicense
}


#relevant both for when creating the Monitor Tools scheduled task, and when running the task
#for the Monitor Tool, we are setting the log name to be a static value, that will eventually become this:
#ServerStatus.txt
$File_Prefix_Monitor = "ServerStatus"


#getting all LOCAL service users
$Services_XMPie_and_uStore = Get-WmiObject win32_service -ErrorAction Stop | Where-Object {($_.Name -Like 'XMP*') -or ($_.Name -Like 'uStore*') -and (($_.startname -Like '.\*') -or (($_.startname -Like '$Machine\*')))} | Select-Object name,startname,state
$Services_XMPie_users_uProduce_uStore=($Services_XMPie_and_uStore | Sort-Object -Unique startname).startname
#getting ALL XMPie non-uStore service users
$Services_users_XMPie_only = (Get-WmiObject win32_service -ErrorAction Stop | Where-Object {($_.Name -Like 'XMP*') -and ($_.startname -Like '*\*')} | Select-Object startname | Sort-Object -Unique startname).startname
$Services_users_XMPie_only_count = ($Services_users_XMPie_only | Measure-Object).Count
#getting ALL uStore service users
$Services_users_uStore_only = (Get-WmiObject win32_service -ErrorAction Stop | Where-Object {($_.Name -Like 'uStore*') -and ($_.startname -Like '*\*')} | Select-Object startname | Sort-Object -Unique startname).startname
$Services_users_uStore_only_count = ($Services_users_uStore_only | Measure-Object).Count

#by default, we are using the SYSTEM service user for scheduled tasks
$Scheduled_tasks_user = "NT AUTHORITY\SYSTEM"
#there is a different logon type for a scheduled task if the tasks runs with the SYSTEM user
$Scheduled_tasks_LogonType = "ServiceAccount"
#if there is a single real service user for XMPie services, then we use it
if ($Services_users_XMPie_only_count -eq 1) {
	$Scheduled_tasks_user = "$Services_users_XMPie_only"
	$Scheduled_tasks_LogonType = "S4U"
}
#otherwise, if there is a single real service user for uStore services, then we use it
elseif ($Services_users_uStore_only_count -eq 1) {
	$Scheduled_tasks_user = "$Services_users_uStore_only"
	$Scheduled_tasks_LogonType = "S4U"
}

#creating a Monitor Tools entry in XMPieDashboard
if ($MonitorCreate) {
	Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "|                  NOTICE!!!                  |" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "|   This action will write to the XMPDB2 DB,  |" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "|  and will create pages in the XMPie folder. |" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "|      Press Y and Enter only if you are      |" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "|                ABSOLUTELY                   |" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "|    Sure that you know what you are doing!   |" -ForegroundColor Yellow -BackgroundColor Red
	Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
	$MonitorConfirm = Read-Host
	if ($MonitorConfirm -match "[yY]") {
		$MonitorASPX = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"> <html xmlns="http://www.w3.org/1999/xhtml"> <head runat="server"> <title></title> <link href="/xmpiedashboard/App_Themes/Default/MonitorTool.css" rel="stylesheet" type="text/css" /> </head> <body> <form id="form1" runat="server"> <div class="toolDiv"> <div class="toolSection"> <div class="toolHeader"> <span class="toolHeaderSpan">Server Status Report</span> </div> <div class="toolContent"><p> <a href="/XMPieDashboard/Monitoring/ServerStatus.txt" target="_blank">View the report</a> </p><p> <a href="/XMPieDashboard/Monitoring/ServerStatus.txt" download>Download the report</a> </p> </div> </div> </form> </body> </html>'
		$MonitorToolsFolder = "$XMPiePathBasic\XMPieDashboard\Monitoring\tools"
		$MonitorToolsFile = "$MonitorToolsFolder\XMPieServerStatus.aspx"
		$MonitorScheduleName = "XMPMonitorServerStatus"
		$MonitorToolsExistingScheduledTaskCheck = Get-ScheduledTask | Where-Object {$_.TaskName -eq "$MonitorScheduleName"}

		#checking for an existing scheduled task
		#we cannot tolerate an existing scheduled task. running more than one instance of the Server Status tool is VERY ill-advised
		if ($MonitorToolsExistingScheduledTaskCheck) {
			Write-Output "`r`nWe are sorry, but There is already a scheduled task called:"
			Write-Output "$MonitorScheduleName"
			Write-Output "`r`nThis script does not cover such a scenario, and will now exit.`r`n"
			Remove-Item -Recurse -Force $LogsFolder
			exit
		}
		else {
			$MonitorScheduleCommand = "`"& {$ScriptPath\$ScriptFileName -Components $Components -LogLocation `"$XMPiePathBasic\XMPieDashboard\Monitoring`" -MonitorRun}`""
			$MonitorScheduledAction = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -command $MonitorScheduleCommand"
			$MonitorScheduledTrigger =  New-ScheduledTaskTrigger -Daily -At 2am
			$MonitorScheduledPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType "ServiceAccount" -RunLevel Highest
			$MonitorScheduledSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)
			Register-ScheduledTask -Action $MonitorScheduledAction -Trigger $MonitorScheduledTrigger -TaskName "$MonitorScheduleName" -Description "XMPie daily run of ServerStatus for the Monitor Tools screen" -Principal $MonitorScheduledPrincipal -Settings $MonitorScheduledSettings
		}

		#checking for an existing ASPX file
		#if the ASPX file already exists, then it is an indication that we are running the process again
		#we leave it up to the user to decide if the contents will be overwritten
		if (Test-Path -Path $MonitorToolsFile) {
			Write-Output "`r`nThe following file exists:"
			Write-Output "$MonitorToolsFile`r`n"
			Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                  WARNING!!!                 |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|    There is already an ASPX file called:    |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|            XMPieServerStatus.aspx           |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "| This means that this is not the first time  |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|       that this process is performed.       |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|     Pressing Y and Enter will overrite      |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|          the contents of the file.          |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|      Are you sure you want to do that?      |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
			$MonitorOverwriteConfirmFile = Read-Host
			if ($MonitorOverwriteConfirmFile -match "[yY]") {
				Write-Output "$MonitorASPX" | Out-File -Encoding utf8 $MonitorToolsFile
				Write-Output "ASPX file created in the following location:`r`n$MonitorToolsFile"
			}
			else {
				Write-Output "`r`nThe script will now exit."
				Remove-Item -Recurse -Force $LogsFolder
				exit
			}
		}
		else {
			Write-Output "$MonitorASPX" | Out-File -Encoding utf8 $MonitorToolsFile
			Write-Output "ASPX file created in the following location:`r`n$MonitorToolsFile"
		}
		$MonitorToolsExistingDBEntryCheck = SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT * FROM [XMPDB2].[XMPie].[TBL_MONITOR_TOOL] WHERE Title = 'Server Status' and ContentType != '-1'"
		$MonitorToolsCreateDBQuery = "INSERT INTO [XMPie].[TBL_MONITOR_TOOL]([MonitorToolTypeID],[UserID],[PrivateParams],[Title],[Column],[RowSequence],[DisplayState],[DisplayPrivateParams],[ContentType],[Content],[Created],[Modified]) VALUES (1,-1,NULL,'Server Status',1,2,0,NULL,0,'<iframe class=`"toolIframe`"  src=`"/xmpiedashboard/Monitoring/tools/XMPieServerStatus.aspx?monitorToolID={0}`"></iframe>',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"

		#checking for an existing DB entry
		#we can tolerate the creation of an additional Monitor Tool. let's go for it...
		if ($MonitorToolsExistingDBEntryCheck) {
			Write-Output "`r`nThere is already a DB entry for Server Status in the XMPDB2 DB, in the table:"
			Write-Output "TBL_MONITOR_TOOL`r`n"
			Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                  WARNING!!!                 |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|     There is already an entry in the DB     |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|      for the Server Status monitor tool     |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|   This means that we are re-creating the    |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|    entire process, including a DB entry.    |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|     Pressing Y and Enter will create an     |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|           additional Monitor Tool           |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                                             |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "|                Are you sure?                |" -ForegroundColor Yellow -BackgroundColor Red
			Write-Host "-----------------------------------------------" -ForegroundColor Yellow -BackgroundColor Red
			$MonitorOverwriteConfirmDB = Read-Host
			if ($MonitorOverwriteConfirmDB -match "[yY]") {
				#$MonitorToolsCreateDBEntry = 
				SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "$MonitorToolsCreateDBQuery"
				Write-Output "DB entry created."
			}
			else {
				Write-Output "`r`nThe script will now exit."
				Remove-Item -Recurse -Force $LogsFolder
				exit
			}
		}
		else {
			SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "$MonitorToolsCreateDBQuery"
			Write-Output "DB entry created."
		}
	}
	else {
		Write-Output "`r`nThe script will now exit."
		Remove-Item -Recurse -Force $LogsFolder
		exit
	}
}
	
	


####################################################
#  starting the checks
####################################################





Write-Host "`r`n`r`nStarting the checks`r`n" -ForegroundColor Green


#Writing general details
wtf "ServerStatus Tool version" $ScriptVersion d

#server name already appears in the report's title
#wtf "Server name" $Machine d

$ParamsNotice = ""
if ($RunSilent) {
	$ParamsNotice = "(the script ran silently with parameters)"
}

if ($Machine -eq $Domain) {
	$UserType = "Local"
}
else {
	$UserType = "Domain"
}
$UserFull = $Domain+"\"+$RunningUser
wtf "Report ran by the $UserType user" $UserFull d
#wtf "User type" $UserType d


#let's check the validity of the machine name, if we're already here
#alphanumeric only, allowing dots and dashes, and no longer than 15 characters
#and le'ts not forget to thank StackOverflow:
#https://stackoverflow.com/q/46911312/722666
#If ($name -match '(\w|\.|-){1,10}') { }
if ($Machine -match '^[a-zA-Z0-9.-]{1,15}$') {
	wtf "Server name is valid" "" g
}
else {
	$ErrorCount++
	wtf "Server name is not valid:" $Machine e "A valid name needs to comply the following conditions:`r`n- Alphanumeric only (dots and dashes are allowed)`r`n- Not longer than 15 characters"
}


$DetailsComputerSystem=(Get-WmiObject -Class Win32_ComputerSystem |Select-Object -property @{N='Computer name';E={$_.Name}}, Domain, Manufacturer, Model | Format-List | out-string).Trim()
wtf "" $DetailsComputerSystem d

#wtf "SQL Server version" $SQLServerEdition d



#local IP address
#good only when there is a single IP address. very problematic
#$IP_Local=(Test-Connection $Machine -count 1).IPv4Address.IPAddressToString
#$IP_Local_output=$IP_Local
#good when there is more than a single internal IP address
$IP_Local_output = Get-NetIPAddress -AddressState Preferred -AddressFamily IPv4| Where-Object { $_.InterfaceAlias -notmatch 'Loopback'} | Select-Object IPAddress
#to test if an address is in the output:
#$IP_Local_output.ipaddress -Contains "10.1.1.32"
#wtf "Local IP address" $IP_Local_output d

#external (public) IP address
# from:
# https://gallery.technet.microsoft.com/scriptcenter/Get-ExternalPublic-IP-c1b601bb
$IP_External=Invoke-RestMethod http://ipinfo.io/json | Select-Object -exp ip

#according to the features we have, we need to see if the relevant services exist
function ServiceSearch ($ServiceToFind = "")
{
	# $ServiceWildcard = "*$ServiceToFind*"
	$ServiceFound = Get-WmiObject win32_service -ErrorAction Stop | Where-Object {$_.Name -Like $ServiceToFind} | Select-Object name,startname,state
	return $ServiceFound
}

#checking for Circle Agent service regardless of the component service test, just in order to use it for some validation
$ServiceExistCircle = ServiceSearch "XMPie Circle Agent"

if ($uProduceSQL) {
	$SQLIPExternal=$SQLIPExternal.trim()
	#these IP checks are only relevant for directors and proxies
	if (($Components -match "[adl]") -and ($Components -notmatch "[t]")) {
		$ExternalAddresses = "Path locator external address: $($SQLIPExternal)`r`nReal internal IP: $($IP_Local_output.ipaddress)`r`nComputer name: $($Machine)"
		Write-Output $ExternalAddresses
		if (($IP_Local_output.ipaddress -Contains "$SQLIPExternal") -or ($SQLIPExternal -eq $Machine)) {
			#Write-Output "internal address is NOT fine"
			if ($ServiceExistCircle) {
				$WarningCount++
				wtf "Path locator external and the REAL local address are identical" "$ExternalAddresses`r`n" w "Circle Agent service is running on this server, so we assume that there should be some real external address"
			}
			else {
				$NoticeCount++
				wtf "Path locator external and the REAL local address are identical" "$ExternalAddresses`r`n" n "Circle Agent service is NOT running on this server, so we assume that this is a Print Only system and this is not an issue"
			}
		}
		else {
			#Write-Output "internal address is probably fine"
			wtf "Path locator external and the real local address are not the same" "" g
		}

		#Regardless of their validity, put the path locator values in the details section
		#wtf "Path locator addresses" "Internal address: $SQLIPInternal`r`nExternal address: $SQLIPExternal" d
	}
}


#Windows version
#NOT FUNCTIONAL
#the Customer Expectations Document is not  a reliable source, as it is not being always updated
#this means that we need to consider if it is even possible / recommended to maintain such a list
#when it is eventually just 'voodoo' that either works or not
#
#use ONLY the following Caption for the reliable identification
#it is a string, but it is accurate
# $WindowsVersionName = (Get-WmiObject -class Win32_OperatingSystem).Caption
#the following SWITCH list is USELESS
#do NOT use it
if (1 -eq 2) {
	$WindowsVersionNumber = (Get-WmiObject -class Win32_OperatingSystem).version
	#in fact, I am only leaving it here as a warning:
	#in several versions, the build number is identical between different OS versions, so we cannot trust it
	switch ($WindowsVersionNumber) {
	   "6.0.6001" {"Windows Server 2008"; break}
	   "6.1.7600.16385" {"Windows 7, RTM"; break}
	   "6.1.7601" {"Windows 7"; break}
	   "6.1.7600.16385" {"Windows Server 2008 R2, RTM"; break}
	   "6.1.7601" {"Windows Server 2008 R2, SP1"; break}
	   "6.2.9200" {"Windows Server 2012"; break}
	   "6.3.9200" {"Windows Server 2012 R2"; break}
	   "6.3.9600" {"Windows Server 2012 R2"; break}
	   "6.2.9200" {"Windows 8"; break}
	   "10.0.10240" {"Windows 10"; break}
	   "10.0.14393" {"Windows Server 2016"; break}
	   "ddd" {"ddd"; break}
	   default {"Something else happened"; break}
	}
}

#creating a list for the details section, in order to condense it
if ($uProduceSQL) {
	$DetailsList = new-object psobject -Property @{
					   SQL = "$SQLServerVersion $SQLServerEdition"
					   LocalIP = $IP_Local_output.ipaddress
					   PathExtIP = $SQLIPExternal
					   PathLocalIP = $SQLIPInternal
					   PEPath = $XMPiePathBasic
					   uStorePath = $uStorePath
					   FFCPath = $FFC_Path
				   }
	$DetailsListLog = ($DetailsList | Format-List @{Label="SQL Server version";Expression={$_.SQL}},@{Label="Local IP address";Expression={$_.LocalIP}},@{Label="Path Locator local IP address";Expression={$_.PathLocalIP}},@{Label="Path Locator external IP address";Expression={$_.PathExtIP}},@{Label="PE path";Expression={$_.PEPath}},@{Label="uStore path";Expression={$_.uStorePath}},@{Label="FFC path";Expression={$_.FFCPath}} | out-string).Trim()
	wtf "" $DetailsListLog d
}
elseif ($Components -match "[r]") {
	wtf "uStore path" $uStorePath d
}

wtf "External IP address" $IP_External d

#checking if the intenal address in the path locator is either the real IP or the name
#relevant only if we are in a director of any kind
if ($Components -match "[ad]") {
	#while we're already here, let's make sure that there are only alphanumeric characters and dots
	if ($SQLIPInternal -match $IPURLValidation) {
		$ErrorCount++
		wtf "Path locator internal address has illegal characters:" "$SQLIPInternal`r`n" e "It must contain ONLY alphanumeric characters and dots"
	}
	#TODO: decide if this check is even relevant. I mean, who are we to decide what is a 'valid' URL for an internet page?
	#if ($SQLIPExternal -match $IPURLValidation) {
	#	$ErrorCount++
	#	wtf "Path locator external address has illegal characters.`r`nIt must contain ONLY alphanumeric characters and dots:" $SQLIPExternal e
	#}
	#and now to check if it is the real IP or not
	$SQLIPInternal=($SQLIPInternal | Format-Table | out-string).Trim()
	$InternalAddresses = "Path locator internal address: $SQLIPInternal`r`n"
	Write-Output $InternalAddresses
	if (($IP_Local_output.ipaddress -Contains "$SQLIPInternal") -or ($SQLIPInternal -eq $Machine)) {
		#Write-Output "internal address is fine"
		wtf "Path locator internal address seems to be fine" $InternalAddresses g
	}
	else {
		#Write-Output "internal address is NOT fine"
		$ErrorCount++
		wtf "(This test is BETA. Unreliable findings)`r`nPath locator internal address is not the real IP or the machine name" "$InternalAddresses" e "Local IP is: $($IP_Local_output.ipaddress)`r`nMachine name is: $Machine"
	}
}


#getting uProduce and/or uStore version and build if possible
# $uProduceVersion = ""
$uProduceBuild = ""
# $uStoreVersion = ""
$uStoreBuild = ""
if ($uProduceSQL) {
	# $uProduceVersion = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT versionNumber FROM [XMPDB2].[XMPie].[TBL_VERSION]"
	$uProduceBuild = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT buildNumber FROM [XMPDB2].[XMPie].[TBL_VERSION]"
}
if ($uStoreSQL) {
	# $uStoreVersion = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [Value] FROM [uStore].[dbo].[Config] where Name = 'AppVersion'"
	$uStoreBuild = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [Value] FROM [uStore].[dbo].[Config] where Name = 'BuildVersion'"
}

if ($SQLDefault) {
	Write-Output "Checking SQL Server version"
	#what edition of SQL Server are we running on?
	$SQLServerEdition = SQLValue $SQLDefault master "$DB_User" "$DB_Password" -sqlText "SELECT SERVERPROPERTY('Edition')"
	#what version of SQL Server are we running on?
	$SQLServerVersionQuery = "SELECT 
	CASE SERVERPROPERTY('ProductMajorVersion')
		When '10' then 'SQL 2008 / 2008R2'
		WHEN '11' THEN 'SQL 2012'
		WHEN '12' THEN 'SQL 2014'
		WHEN '13' THEN 'SQL 2016'
		WHEN '14' THEN 'SQL 2017'
		WHEN '15' THEN 'SQL 2019'
		ELSE 'unknown'
	END as 'Version'"
	$SQLServerVersion = SQLValue $SQLDefault master "$DB_User" "$DB_Password" -sqlText $SQLServerVersionQuery
	#check if this is SQL Server Express edition
	$SQLServerExpress = SQLValue $SQLDefault master "$DB_User" "$DB_Password" -sqlText "IF ((SELECT @@VERSION) like '%express%') Begin SELECT SERVERPROPERTY('Edition') END"

	#take DB sizes while we're at it. for future reference. a suggestion made by Svetlana Bogush
	#DB sizes
	# $SQLDBSizesQuery = "SELECT DB_NAME(smf.database_id) AS Database_Name, smf.Name AS File_Name, sdb.collation_name, smf.Physical_Name AS Physical_Path, (size*8)/1024 Size_MB FROM sys.master_files smf left join sys.databases sdb on sdb.name=smf.Name order by Size_MB desc"
	$SQLDBSizesQuery = "SELECT DB_NAME(smf.database_id) AS Database_Name, smf.Name AS File_Name, sdb.collation_name, smf.Physical_Name AS Physical_Path, (size*8)/1024 Size_MB FROM sys.master_files smf left join sys.databases sdb on sdb.name=smf.Name order by Size_MB desc"
	#the table is too wide, so not all columns are showing. adding a Width to the Out-String and setting that table to show all columns with Autosize solves that	
	$SQLDBSizes = (SQLProcess $SQLDefault master "$DB_User" "$DB_Password" -sqlText $SQLDBSizesQuery | Format-Table -Property * -AutoSize | Out-String -Width 4096).Trim()
	wtf "SQL DB sizes" $SQLDBSizes i

}


#if this is SQL Server Express, then check that we do not have problematic DB sizes
#problematic = over 8GB
#but first, let's see if this is even an Express installation
if ($SQLServerExpress) {
Write-Output "SQL Server: checking DB sizes in SQL Express"
	#it is an Express installation, so let's start the size checks
	# $LargeDBs = SQLProcess $SQLDefault master "$DB_User" "$DB_Password" -sqlText "SELECT CAST((F.size*8)/1024 AS VARCHAR(26)) AS FileMB, D.name, F.Name AS FileType, F.state_desc AS OnlineStatus FROM sys.master_files F INNER JOIN sys.databases D ON D.database_id = F.database_id where F.size > 1024000 and type_desc != 'LOG' ORDER BY F.size desc"
	$LargeDBs = (SQLProcess $SQLDefault master "$DB_User" "$DB_Password" -sqlText "SELECT CAST((F.size*8)/1024 AS VARCHAR(26)) AS FileMB, D.name, F.Name AS FileType, F.state_desc AS OnlineStatus FROM sys.master_files F INNER JOIN sys.databases D ON D.database_id = F.database_id where F.size > 1024000 and type_desc != 'LOG' ORDER BY F.size desc" | Format-Table | out-string).Trim()
	if ($LargeDBs) {
		$LargeDBs10G = (SQLProcess $SQLDefault master "$DB_User" "$DB_Password" -sqlText "SELECT CAST((F.size*8)/1024 AS VARCHAR(26)) AS FileMB, D.name, F.Name AS FileType, F.state_desc AS OnlineStatus FROM sys.master_files F INNER JOIN sys.databases D ON D.database_id = F.database_id where F.size > 1280000 and type_desc != 'LOG' ORDER BY F.size desc" | Format-Table | out-string).Trim()
		if ($LargeDBs10G) {
			$ErrorCount++
			$LargeDBs10GCount = SQLValue $SQLDefault master "$DB_User" "$DB_Password" -sqlText "SELECT count(*) FROM (SELECT CAST((F.size*8)/1024 AS VARCHAR(26)) AS FileMB, D.name, F.Name AS FileType, F.state_desc AS OnlineStatus FROM sys.master_files F INNER JOIN sys.databases D ON D.database_id = F.database_id where F.size > 1280000 and type_desc != 'LOG') large10gb"
			wtf "There are $LargeDBs10GCount large DBs data files in an SQL Server Express (over 10GB)" $LargeDBs e "SQL Server Express Edition limits DB size to a maximum of 10GB.`r`nBeyond that, you will not be able to write any more data to the DB, and it can have dire consequences"
		}
		else {
			$WarningCount++
			$LargeDBsCount = SQLValue $uStoreSQL uStore "$DB_User" "$DB_Password" -sqlText "SELECT count(*) FROM (SELECT CAST((F.size*8)/1024 AS VARCHAR(26)) AS FileMB, D.name, F.Name AS FileType, F.state_desc AS OnlineStatus FROM sys.master_files F INNER JOIN sys.databases D ON D.database_id = F.database_id where F.size > 1024000 and type_desc != 'LOG') large"
			wtf "There are $LargeDBsCount large DBs data files in an SQL Server Express (over 8GB)" $LargeDBs w "SQL Server Express Edition limits DB size to a maximum of 10GB.`r`nBeyond that, you will not be able to write any more data to the DB, and it can have dire consequences"
		}
	}
	else {
		wtf "There are no large DBs data files in an SQL Server Express (over 8GB)" "" g
	}
}


#check if there are any DBs that are from a different compatibility level
if ($Components -match "[sar]") {
	#if it is a uStore server not on the director, then use the uStore DB credentials
	#otherwise, use the regular credentials
	Write-Output "SQL: checking DB compatibility level"
	if (($Components -match "[r]") -and ($Components -NotMatch "[a]")) {
		$CompatUser = $DB_User_uStore
		$CompatPass = $DB_Password_uStore
	}
	else {
		$CompatUser = $DB_User
		$CompatPass = $DB_Password
	}

	#compatibility level tests
	#current SQL server compatibility level
	# below is the old query. it relied on the compatibility level set in the MASTER DB, which is rubbish, since...
	# the compatibility is not being updated when SQL Server is upgraded
	# $SQLCompatibilityCurrentQuery = "select cmptlevel from sysdatabases where name = db_name()"
	#another option is to go for the actual version, and work with CASE
	# $SQLCompatibilityCurrentQuery = "select 'ServerCompatibility' = CASE CAST(SERVERPROPERTY('ProductMajorVersion')  AS DECIMAL)
	# 	WHEN 6.5  THEN '65' 
	# 	WHEN 7  THEN '70'
	# 	WHEN 8  THEN '80'
	# 	WHEN 9  THEN '90'
	# 	WHEN 10 THEN '100'
	# 	WHEN 10.5 THEN '100'
	# 	WHEN 11 THEN '11'
	# 	WHEN 12 THEN '120'
	# 	WHEN 13 THEN '130'
	# 	WHEN 14 THEN '140'
	# 	WHEN 15 THEN '150'
	# 	ELSE 'Unknown'
	# END"
	#eventually, this is the query used for calculating the compatibility level
	#IMPORTANT! it relies on the compatibility to equal the major version times 10
	#if there is an issue with this, then you should probably go back to the CASE above
	#solution from here:
	#https://stackoverflow.com/a/62320576/722666
	$SQLCompatibilityCurrentQuery = "SELECT PARSENAME(CAST(SERVERPROPERTY('ProductVersion') AS varchar(20)),4) * 10 AS ServerCompatibility;"
	#$SQLCompatibilityCurrent = SQLProcess $uProduceSQL master "$CompatUser" "$CompatPass" -sqlText "$SQLCompatibilityCurrentQuery" values
	$SQLCompatibilityCurrent = SQLValue  $SQLDefault master "$CompatUser" "$CompatPass" -sqlText "$SQLCompatibilityCurrentQuery"
	#all DBs compatibility level, of those that are different from the current server level
	$SQLCompatibilityAllQuery = "SELECT name AS 'DB Name', compatibility_level as 'Version code' FROM sys.databases"
	$SQLCompatibilityProblematicQuery = "select top 20 name as 'DB Name', compatibility_level as 'Version code' , 'Compatible with' = 
	CASE compatibility_level
		WHEN 65  THEN 'SQL 6.5' 
		WHEN 70  THEN 'SQL 7.0'
		WHEN 80  THEN 'SQL 2000'
		WHEN 90  THEN 'SQL 2005'
		WHEN 100 THEN 'SQL 2008/R2'
		WHEN 110 THEN 'SQL 2012'
		WHEN 120 THEN 'SQL 2014'
		WHEN 130 THEN 'SQL 2016'
		WHEN 140 THEN 'SQL 2017'
		WHEN 150 THEN 'SQL 2019'
		ELSE 'new unknown - '+CONVERT(varchar(10),compatibility_level)
	END
	from sys.databases
	where compatibility_level < " + "$SQLCompatibilityCurrent"
	$SQLCompatibilityProblematicNamesQuery = "select name
	from sys.databases
	where compatibility_level < " + "$SQLCompatibilityCurrent"
	$SQLCompatibilityProblematic = (SQLProcess $SQLDefault master "$CompatUser" "$CompatPass" -sqlText $SQLCompatibilityProblematicQuery | Format-Table | out-string).Trim()
	$SQLCompatibilityProblematicNames = (SQLProcess $SQLDefault master "$CompatUser" "$CompatPass" -sqlText $SQLCompatibilityProblematicNamesQuery | Format-List | out-string).Trim()

	if ($SQLCompatibilityProblematic) {
		$NoticeCount++
		$SQLCompatibilityChange  = ""

		foreach ( $SQLCompatibilityProblematicName in $($SQLCompatibilityProblematicNames -split "`r`n").Trim() ) {
			if ($SQLCompatibilityProblematicName -and $SQLCompatibilityProblematicName -ne "name" -and $SQLCompatibilityProblematicName -ne "----") {
					# this is a deprecated method of changing compatibility level
					# $SQLCompatibilityChangeText =  "EXEC sp_dbcmptlevel '" + $SQLCompatibilityProblematicName + "', " + $SQLCompatibilityCurrent + "`r`n"
					$SQLCompatibilityChangeText =  "ALTER DATABASE `"" + $SQLCompatibilityProblematicName + "`" SET COMPATIBILITY_LEVEL = " + $SQLCompatibilityCurrent + "`r`n"
					$SQLCompatibilityChange +=  $SQLCompatibilityChangeText
			}
		}
		$SQLCompatibilityProblematicText = $SQLCompatibilityProblematic | Out-String
		$CompatibilityProblematicWarning = "There are DBs that have a compatiblity level different than the current one, which is $SQLCompatibilityCurrent.`r`n`r`nList of DBs with problematic compatibility level (the following list is limited to 20 records):`r`n$SQLCompatibilityProblematicText"
		wtf "$CompatibilityProblematicWarning" "" n "You can view them using this Query:`r`n$SQLCompatibilityAllQuery`r`n`r`nEDIT BEFORE RUNNING the following query, and use ONLY FOR XMPie databases!`r`n`r`nTo change the compatibility via a query, you can use this query :`r`n$SQLCompatibilityChange"
	}
	else {
		wtf "All DBs are the same compatibility level as the current instance: $SQLCompatibilityCurrent" "" g
	}
}



#check if Windows Firewall is on in any aspect
#from:
#https://blogs.technet.microsoft.com/heyscriptingguy/2012/10/28/powertip-use-powershell-to-enable-the-windows-firewall/
$FireWallOn = ""
$FireWallOn = Get-NetFirewallProfile | Where-Object {$_.Enabled -Like '*true*'} | Format-Table name, enabled
$FireWallAll = ""
$FireWallAll = (Get-NetFirewallProfile | Format-Table name, enabled | out-string).Trim()
if ($FireWallOn) {
	$NoticeCount++
	wtf "Windows firewall is on" $FireWallAll n
}
else {
	wtf "Windows firewall is off. Status:" $FireWallAll g
}

#take all LOCAL drives and their size and free space, and show it
$DrivesSpace = (Get-WmiObject Win32_LogicalDisk | Select-Object @{L='Drive';E={$_.DeviceID}},@{L='Size (GB)';E={[math]::truncate($_.Size / 1GB)}},@{L='Free space (GB)';E={[math]::truncate($_.freespace / 1GB)}} | Format-Table | out-string).Trim()
wtf "Local drives and their free space:" $DrivesSpace i

#and now we will actually check if we should alert regarding free space
# $DrivesEachAll = Get-WmiObject Win32_LogicalDisk -Filter "DriveType='3'" | ForEach-Object {
# 	$DriveName = $_.DeviceID
# 	$DriveTotalSpace = [math]::truncate($_.size / 1GB)
# 	$DriveFreeSpace = [math]::truncate($_.freespace / 1GB)
# 	$DriveFreePercentage = ""
# 	if (($DriveFreeSpace -eq 0) -or ($DriveFreeSpace -lt 1)) {
# 		$ErrorCount++
# 		wtf "Drive $DriveName is completely out of space!" "" e
# 	}
# 	else {
# 		$DriveFreePercentage = [math]::truncate($DriveFreeSpace / $DriveTotalSpace * 100)
# 		if (($DriveFreePercentage -lt 10) -or ($DriveFreeSpace -lt 20)) {
# 			$DriveFreeDetails = $DriveName + " - Total " + $DriveTotalSpace + "GB - Left " + $DriveFreeSpace + "GB (" + $DriveFreePercentage + "%)"
# 			$WarningCount++
# 			wtf "Drive $DriveName is very low on space" "$DriveFreeDetails" w
# 		}
# 	}
# }


#check XMPie folders sizes
#this is done by running a dummy process of RoboCopy that provides a summary
#most methods recommend using Get-ChildItem but this is an extremely iefficient way that takes a lot of time in large systems
#most of the code was taken from:
#https://www.linkedin.com/pulse/technical-thursdays-get-directory-sizes-stupidly-fast-carlos-nunez
#the thousands separator formatting was taken from the Scripting Guy:
#https://blogs.technet.microsoft.com/heyscriptingguy/2011/03/03/use-powershell-regular-expressions-to-format-numbers/
function Get-DirectorySizeWithRobocopy {
	param (
#	[Parameter(Mandatory=$true)]
	[string]$folder,
	[string]$units = "Gb",
	[string]$fullOutput = "n" #n = Number and t = Text summary
	)

	$fileCount = 0 ; 
	$totalBytes = 0 ; 
	robocopy /l /nfl /ndl $folder \\localhost\C$\nul /e /bytes | Where-Object{ 
	$_ -match "^[ \t]+(Files|Bytes) :[ ]+\d" 
	} | ForEach-Object{ 
	$line = $_.Trim() -replace ' :',':' -replace ' +',',' ; 
	# $line = $_.Trim() -replace '[ ]{2,}',',' -replace ' :',':' ; 
	$value = $line.split(',')[1] ; 
	if ( $line -match "Files:" ) { 
		$fileCount = $value }
	else {
		$totalBytes = $value
	} 
	} ;
	if ($units -eq 'Mb') {
		$totalWeight = [math]::round($totalBytes /1Mb)
	}
	else {
		$totalWeight = [math]::round($totalBytes /1Gb)
	}
	$fileCounts = $fileCount -replace '(?<=\d)(?=(\d{3})+\b)', ',' 
	# [pscustomobject]@{GB=$totalGB;Files=$fileCounts;Path=$folder;}
	if ($fullOutput -eq 't') {
		$SizeOutput = "Path: $folder`r`nSize: $totalWeight $units`r`nFiles: $fileCounts"
	}
	else {
		$SizeOutput = "$totalWeight"
	}
	return $SizeOutput
}

#getting the C: drive free space
$DriveCFree = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object FreeSpace
$DriveCFreeShow = [math]::round($DriveCFree.FreeSpace /1MB)
# [float]$DriveCFreeSpace = [math]::round($DriveCFree.FreeSpace /1MB)
[float]$DriveCFreeSpaceHalf = [math]::round($DriveCFree.FreeSpace /2MB)

#sadly, checking the folders size took too long in large systems. we found it in live client systems
#it is really a shame that Windows doesn't have any function like GNU/Linux's 'du' to do it quickly
#well, anyway, now you know why the following sections are commented out
# if ($XMPiePathBasic) {
	# Write-Output "Checking XMPie folder size"
	# $XMPiePathSize = Get-DirectorySizeWithRobocopy ($XMPiePathBasic)
	# wtf "XMPie folder size:" $XMPiePathSize i
# }

# if ($Components -match "[r]") {
	# if ($uStorePath) {
		# Write-Output "Checking uStore folder size"
		# $uStorePathSize = Get-DirectorySizeWithRobocopy ($uStorePath)
		# wtf "uStore folder size:" $uStorePathSize i
	# }
# }


#tests within the XMPLogs folder
#uStore log tests are further down, due to the size of their output

#checking the size of the XMPLogs folder, if it exists
#if the XMPLogs is anywhere else (does not exist) then the test will be skipped as well
if (Test-Path -Path 'C:\XMPLogs') {
#the test: if it is larger than half of the remaining free space in the c: drive
	Write-Output "Checking the C:\XMPLogs folder weight"
	# $XMPLogsSpace = Get-ChildItem 'c:\XMPLogs' -recurse | Measure-Object -sum length | select Sum
	[float]$XMPLogsSpace = Get-DirectorySizeWithRobocopy -folder 'c:\XMPLogs' -units 'Mb'
	#$XMPLogsSpaceSum = [math]::truncate($XMPLogsSpace.Sum /1MB)
	$LogsVSFree = "Folder C:\XMPLogs: $XMPLogsSpace mb`r`nDrive C free space: $DriveCFreeShow mb"
	if ($XMPLogsSpace -gt $DriveCFreeSpaceHalf) {
		$WarningCount++
		wtf "Folder C:\XMPLogs is larger than half of the free space remaining in drive C" $LogsVSFree w "You should consider deleting old log files and disable any debug logging"
	}
	elseif ($XMPLogsSpace -gt 5000) {
		$NoticeCount++
		wtf "Folder C:\XMPLogs is very large: $XMPLogsSpace mb`r`n" "" n "Even though the logs folder is still less than half of the free space in drive C:, you should consider deleting old log files and disable any debug logging"
	}
	else {
		wtf "The size of the folder C:\XMPLogs is normal:" $LogsVSFree g
	}
}
else {
	$ErrorCount++
	wtf "The folder C:\XMPLogs does not exist" "" e
}


#TODO: ping tests to all owners that are not the localhost
#sometimes pings are blocked, so we need to either think of a solution or abandon this test
#All the License table. We are looking into the owner column:
#$LicenseOwners = SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT DISTINCT [Owner] FROM [XMPDB2].[XMPie].[TBL_LICENSE] WHERE Owner != ''"
#$LicenseOwners
#$LicenseOwners1 = Write-Output $LicenseOwners | select-string "TALLIN (10.1.1.31)"
#$LicenseOwners1
#[regex]::Matches($LicenseOwners, '(([^/)]+))') |ForEach-Object { $_.Groups[1].Value }
#$LicenseOwners2


#check if XMPie related software was installed/repaired/modified recently
#the problem was that the InstallDate is not considered as a date format, and I could not calculate day differences with it
#got the solution from StackOverflow:
#https://stackoverflow.com/a/58691715/722666
if ($Days) {
	$SoftwareInstall_Days = $Days
}
else {
	$SoftwareInstall_Days = 30
}
$TheDate = (([datetime]::Now))

# Try to parse dates.
$Installed_Software_NonFormatted.ForEach({
	# add more formats if you need
	[string[]] $formats = @("yyyyMMdd","MM/dd/yyyy")

	$installDate = $_.InstallDate
	$installedDateObj = $null;    
	$formats.ForEach({ [DateTime] $dt = New-Object DateTime; if([datetime]::TryParseExact($installDate, $_, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {  $installedDateObj = $dt} }); 
	$_.InstallDateObj = $installedDateObj
})

$Installed_SoftwareNonWow_NonFormatted.ForEach({
	# add more formats if you need
	[string[]] $formats = @("yyyyMMdd","MM/dd/yyyy")

	$installDate = $_.InstallDate
	$installedDateObj = $null;    
	$formats.ForEach({ [DateTime] $dt = New-Object DateTime; if([datetime]::TryParseExact($installDate, $_, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$dt)) {  $installedDateObj = $dt} }); 
	$_.InstallDateObj = $installedDateObj
})

$XMPie_installed_recently_Wow= @()
$XMPie_installed_recently_Wow=($Installed_Software_NonFormatted |
Where-Object {($_.DisplayName -match ('XMPie') -or $_.Publisher -match ('XMPie') -or $_.DisplayName -match ('Circle') -or $_.DisplayName -match ('Xerox') -or $_.DisplayName -match ('FreeFlow') -or $_.DisplayName -match ('Helicon') -and ($_.InstallDateObj -ne $null) -and (($TheDate - $_.InstallDateObj).Days -le $SoftwareInstall_Days))}) 

$XMPie_installed_recently_NonWow= @()
$XMPie_installed_recently_NonWow=($Installed_SoftwareNonWow_NonFormatted |
Where-Object {($_.DisplayName -match ('XMPie') -or $_.Publisher -match ('XMPie') -or $_.DisplayName -match ('Circle') -or $_.DisplayName -match ('Xerox') -or $_.DisplayName -match ('FreeFlow') -or $_.DisplayName -match ('Helicon') -and ($_.InstallDateObj -ne $null) -and (($TheDate - $_.InstallDateObj).Days -le $SoftwareInstall_Days))})

$XMPie_installed_recently_disclaimer = ""
if(( $null -ne $XMPie_installed_recently_Wow -and @($XMPie_installed_recently_Wow).count -gt 0 ) -or ( $null -ne $XMPie_installed_recently_NonWow -and @($XMPie_installed_recently_NonWow).count -gt 0 )) {
	$NoticeCount++
	# $XMPie_installed_recently_string_Wow = ($XMPie_installed_recently_Wow | Format-Table -AutoSize | out-string).Trim()
	# $XMPie_installed_recently_NonWow_string = ($XMPie_installed_recently_NonWow | Format-Table -AutoSize | out-string).Trim()
	#NO TRIMMING! nothing major, actually. it is just that trimming causes the output to be too condensed, and difficult to decypher
	$XMPie_installed_recently_string_Wow = $XMPie_installed_recently_Wow | Format-Table -AutoSize | out-string
	$XMPie_installed_recently_NonWow_string = $XMPie_installed_recently_NonWow | Format-Table -AutoSize | out-string
	$XMPie_installed_recently_disclaimer = "Please note that there is some XMPie related software installed and/or repaired / modified in the last $SoftwareInstall_Days days, so it may be the reason for the changes"
	wtf "Some XMPie related software was installed and/or repaired / modified in the last $SoftwareInstall_Days days.`r`nThese are the items:`r`n$XMPie_installed_recently_string_Wow$XMPie_installed_recently_NonWow_string" "" n
}
else {
	wtf "No XMPie related software was recently installed and/or repaired / modified" "" g
}


#uStore: checking if there are recently installed patches
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		Write-Output "uStore: checking if there are recently installed patches"
		if ($Days) {
			$uStoreRecentPatchesInstalledDays = $Days
		}
		else {
			$uStoreRecentPatchesInstalledDays = 14
		}
		$SQLuStoreRecentPatches = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [PatchID],SUBSTRING([Description],1,60) AS Description,[DateModified] FROM [uStore].[dbo].[Patches] where DateModified > DATEADD(day, -$uStoreRecentPatchesInstalledDays, GETDATE())" | Format-Table | out-string).Trim()
		if ($SQLuStoreRecentPatches) {
			$NoticeCount++
			wtf "uStore: patches were installed in the last $uStoreRecentPatchesInstalledDays days:" "$SQLuStoreRecentPatches`r`n" n "$XMPie_installed_recently_disclaimer"
		}
		else {
			wtf "uStore: no patches were installed in the last $uStoreRecentPatchesInstalledDays days" "" g
		}
	}
}


#uProduce: checking if there are recently installed patches
if ($Components -match "[adtg]") {
	if ($uProduceSQL) {
		Write-Output "uProduce: checking if there are recently installed patches"
		if ($Days) {
			$uProduceRecentPatchesInstalledDays = $Days
		}
		else {
			$uProduceRecentPatchesInstalledDays = 14
		}
		#limiting the Description to 60 characters, in order to keep the results readable
		$SQLuProduceRecentPatches = (SQLProcess $uProduceSQL XMPDB2 "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [PatchID],SUBSTRING([Description],1,60) AS Description,[BugID],[CreatedForVersion] AS ForVersion,[DateModified] AS Modified,[Status] FROM [XMPDB2].[XMPie].[Patches] where DateModified > DATEADD(day, -$uProduceRecentPatchesInstalledDays, GETDATE())" | Format-Table | out-string).Trim()
		if (($SQLuProduceRecentPatches) -and ($SQLuProduceRecentPatches -ne "An error has occured while trying to perform a query. For the full error, uncomment the line below, in the function SQLProcess")) {
			$NoticeCount++
			wtf "uProduce: patches were installed in the last $uProduceRecentPatchesInstalledDays days:" "$SQLuProduceRecentPatches`r`n" n "$XMPie_installed_recently_disclaimer"
		}
		else {
			wtf "uProduce: no patches were installed in the last $uProduceRecentPatchesInstalledDays days" "" g
		}
	}
}



#checking how old a file is, in days (file age)
#provide FULL path, please
function Get-File-Modification-Age {
	param (
	[string]$file
	)
	#this function does NOT check if the file exists. you should do it yourself, since you may want to alert the user about it
	$ModificationAge = ((get-date) - (Get-ChildItem $file).LastWriteTime).days
	return $ModificationAge
}



#look for the application path
# PE: check for presence of key first
#irrelevant if we are running on an SQL only server, since it does have the SQL details, but no path for uProduce files
#used to check if the Components ARE "s", however it was problematic when MC or other components were there
# if (($uProduceSQL) -and ($Components -match "[adt]")) {
#if the server is a director of any kind, or an extension, or has uImage, then we need to check for the path
if ($Days) {
	$uProduceWebConfigModifiedDays = $Days
}
else {
	$uProduceWebConfigModifiedDays = 30
}
$uProduceWebConfigModifiedCount = 0
if ($Components -match "[adtg]") {
	if ($XMPiePath) {
		Write-Output "The PE application path is: $XMPiePathBasic"
		#wtf "The PE application path is:" "$XMPiePathBasic" d
		
		#IMPORTANT
		#file tests are very expensive in terms of performance and time, and this is the main reason for NOT performing all the tests we would like to
		
		#check if there are blocked files in PE 'important' folders
		#TODO: add a check for leading spaces in file names, here and in uStore and MC as well:
		#Get-ChildItem -Path "PATH" -Recurse | foreach-object {if($_.name.length -ne $_.name.trim().length) { "$($_.name)"}}
		
		#TODO: check for read-only files. need to decide if *.config files should be included or not, since by default we mark them as read only
		#from: https://blogs.technet.microsoft.com/heyscriptingguy/2012/06/19/use-powershell-to-find-and-change-read-only-files/
		#gci -Include *.dll, *.aspx, *.ashx, *.asmx, *.xml, *.txt, *.exe, *.lib, *.config -Recurse -Path "PATH" | Where-Object {$_.isreadonly -Like '*true*'}| select fullname,isreadonly

		#uProduce web.config files modification time
		Write-Output "Checking for recently modified web.config files in the uProduce application folders"
		$uProducePathsCheckWebConfig = @("$XMPiePathBasic\XMPieDashboard","$XMPiePathBasic\XMPieMonitorToolsAPIWCF","$XMPiePathBasic\XMPieWSAPI")
		[string]$uProduceWebConfigModifiedList = ""
		foreach ($uProducePathCheckWebConfig in $uProducePathsCheckWebConfig) {
			$uProducePathCheckWebConfigFile = "$($uProducePathCheckWebConfig)\web.config"
			if (Test-Path -Path $uProducePathCheckWebConfigFile) {
				$FileAge = Get-File-Modification-Age "$uProducePathCheckWebConfigFile"
				if ($FileAge -lt $uProduceWebConfigModifiedDays) {
					$uProduceModifiedListItem =  "File is $FileAge days old: $uProducePathCheckWebConfigFile"
					$uProduceWebConfigModifiedCount ++
					$uProduceWebConfigModifiedList = "$($uProduceWebConfigModifiedList)`r`n$($uProduceModifiedListItem)"
				}
			}
		}
		if ($uProduceWebConfigModifiedCount -eq 0) {
			wtf "None of the relevant web.config files in the uProduce folders were modified in the last $uProduceWebConfigModifiedDays days" "" g
		}
		elseif ($XMPie_installed_recently_disclaimer) {
			$NoticeCount++
			wtf "uProduce: There are web.config files that were changed in the last $uProduceWebConfigModifiedDays days:" "$uProduceWebConfigModifiedList`r`n" n "$XMPie_installed_recently_disclaimer"
		}
		else {
			$WarningCount++
			wtf "uProduce: There are web.config files that were changed in the last $uProduceWebConfigModifiedDays days:" "$uProduceWebConfigModifiedList`r`n" w
		}


		#TODO: check if all of these folders are relevant in every case, and if not then when should they be checked
		Write-Output "Checking for blocked files in the PE application folders"
		# $PEPathsCheck = @("$XMPiePathBasic\XMPieDashboard","$XMPiePathBasic\XMPieEmail","$XMPiePathBasic\XMPieExec","$XMPiePathBasic\XMPieMonitorToolsAPIWCF","$XMPiePathBasic\XMPieWSAPI")
		$PEPathsCheck = @("$XMPiePathBasic\XMPieDashboard","$XMPiePathBasic\XMPieEmail","$XMPiePathBasic\XMPieExec","$XMPiePathBasic\XMPieMonitorToolsAPIWCF","$XMPiePathBasic\XMPieWSAPI")
		$LockedCount = 0
		foreach ($PEPathCheck in $PEPathsCheck) {
			if (Test-Path -Path $PEPathCheck) {
				#we are ignoring the old WebHelp folder. with older clients, many files have a wrong mark as downloaded from the internet
				$BlockedFiles = ""
				$BlockedFiles = Get-ChildItem $PEPathCheck -Recurse | Where-Object { $_.FullName -inotmatch 'WebHelp' } | Where-Object -FilterScript{[System.Security.Policy.Zone]::CreateFromUrl($_.FullName).SecurityZone -eq 'Internet'}
				$BlockedFilesString = "Get-ChildItem $PEPathCheck -Recurse | ? { `$_.FullName -inotmatch 'WebHelp' } | Where-Object -FilterScript{[System.Security.Policy.Zone]::CreateFromUrl(`$_.FullName).SecurityZone -eq 'Internet'}"
				if ($BlockedFiles) {
					$LockedCount ++
					$ErrorCount++
					$BlockedFilesBackslashMessage = ""
					$BlockedFilesBackslashCheck = [Regex]::Matches($uStorePathCheck, "^\\\\")
					if ($BlockedFilesBackslashCheck) {
						$BlockedFilesBackslashMessage = "Notice: This specific path is a network path. In some cases, some servers will always indicate that the files are blocked, due to Internet security settings.`r`n"
					}
					wtf "There are files that are marked as blocked (downloaded from the internet)`r`nin the folder $PEPathCheck" "" e "$BlockedFilesBackslashMessage You can see them using this command:`r`n$BlockedFilesString`r`n`r`nTo unblock these files, you can use the following command:`r`ndir -Path `"$PEPathCheck`" -Recurse | Unblock-File"
				}
			}
		}
		if ($LockedCount -eq 0) {
			wtf "None of the files in the PE folder are blocked" "" g
		}
	}
	else {
		Write-Output "Could not find a PE application path"
		$ErrorCount++
		wtf "There is no PE application path in the system registry" "" e
	}
}

#uProduce: checking if local shared folder is available
Write-Output "uProduce: checking if local shared folder is available"
#relevant for any type of Director, and not an extension by accident
if ((($Components -match "[ad]") -and ($Components -notmatch "[t]")) -or ($Components -match "[z]")) {
	$ShareXMPieExists = LocalShareCheck 'XMPie'
	if ($ShareXMPieExists) {
		if (Test-Path -Path '\\localhost\XMPie') {
			wtf "uProduce XMPie local shared folder is accessible" "" "g"
		}
		else {
			wtf "uProduce XMPie local shared folder exists in the server settings, but it is not accessible. Path:`r`n\\localhost\XMPie" "`r`n" "e" "You should check in Computer Management if there is a shared folder with the name XMPie.`r`nIf there is a shared folder with this name, then check for security settings.`r`nYou may need to run a Modify of the uProduce installation in order to make sure that everything is in order."
		}
	}
	else {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`n`r`nuProduce XMPie local shared folder does not exist in the server settings. Path:`r`n\\localhost\XMPie`r`nYou should check in Computer Management if there is a shared folder with the name XMPie.`r`nYou may need to run a Modify of the uProduce installation in order to make sure that everything is in order.`r`n"
		}
		else {
			wtf "uProduce XMPie local shared folder does not exist in the server settings. Path:`r`n\\localhost\XMPie" "`r`n" "e" "You should check in Computer Management if there is a shared folder with the name XMPie.`r`nYou may need to run a Modify of the uProduce installation in order to make sure that everything is in order."
		}
	}
}


#XMPL Server: checking if local shared folder is available
Write-Output "XMPL Server: checking if local shared folder is available"
#relevant for any type of Director, and not an extension by accident
if ($Components -match "[l]") {
	$ShareXMPieExists = LocalShareCheck 'XMPieWebSites'
	if ($ShareXMPieExists) {
		if (Test-Path -Path '\\localhost\XMPieWebSites') {
			wtf "XMPL Server local shared folder is accessible" "" "g"
		}
		else {
			wtf "XMPL Server local shared folder exists in the server settings, but it is not accessible. Path:`r`n\\localhost\XMPieWebSites" "`r`n" "e" "You should check in Computer Management if there is a shared folder with the name XMPieWebSites.`r`nIf there is a shared folder with this name, then check for security settings.`r`nYou may need to run a Modify of the XMPL Server installation in order to make sure that everything is in order."
		}
	}
	else {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`n`r`nXMPL Server local shared folder does not exist in the server settings. Path:`r`n\\localhost\XMPieWebSites`r`nYou should check in Computer Management if there is a shared folder with the name XMPieWebSites.`r`nYou may need to run a Modify of the XMPL Server installation in order to make sure that everything is in order.`r`n"
		}
		else {
			wtf "XMPL Server local shared folder does not exist in the server settings. Path:`r`n\\localhost\XMPieWebSites" "`r`n" "e" "You should check in Computer Management if there is a shared folder with the name XMPieWebSites.`r`nYou may need to run a Modify of the XMPL Server installation in order to make sure that everything is in order."
		}
	}
}


# uStore file checks
# I made sure that if there is no registry key for uStore, then there is no value, and there is no check
# this way we can be sure that it will run only when the test is relevant
if ($Days) {
	$uStoreWebConfigModifiedDays = $Days
}
else {
	$uStoreWebConfigModifiedDays = 30
}
$uStoreWebConfigModifiedCount = 0

if ($Components -match "[r]") {
	if ($uStorePath) {
		Write-Output "The uStore application path is: $uStorePath"
		#wtf "The uStore application path is:" "$uStorePath" d

		#uStore web.config files modification time
		Write-Output "Checking for recently modified web.config files in the uStore application folders"
		$uStorePathsCheckWebConfig = @("$uStorePath\AdminApp","$uStorePath\API\uStoreRestAPI","$uStorePath\Common\uStore.CommonControls","$uStorePath\CustomerApp","$uStoreSharedLocation\Skins\Images","$uStoreSharedLocation\Themes\Global\Fonts","$uStoreSharedLocation\Themes","$uStoreSharedLocation\ThemeCustomizations")
		[string]$uStoreWebConfigModifiedList = ""
		foreach ($uStorePathCheckWebConfig in $uStorePathsCheckWebConfig) {
			$uStorePathCheckWebConfigFile = "$($uStorePathCheckWebConfig)\web.config"
			if (Test-Path -Path $uStorePathCheckWebConfigFile) {
				$FileAge = Get-File-Modification-Age "$uStorePathCheckWebConfigFile"
				if ($FileAge -lt $uStoreWebConfigModifiedDays) {
					$ModifiedListItem =  "File is $FileAge days old: $uStorePathCheckWebConfigFile"
					$uStoreWebConfigModifiedCount ++
					$uStoreWebConfigModifiedList = "$($uStoreWebConfigModifiedList)`r`n$($ModifiedListItem)"
				}
			}
		}

		
		
		#check if there are blocked files in uStore 'important' folders
		#TODO: check if all of these folders are relevant in every case, and if not then when should they be checked
		Write-Output "Checking for blocked files in the uStore application folders"
		$uStorePathsCheck = @("$uStorePath\AdminApp","$uStorePath\API","$uStorePath\Common","$uStorePath\CustomerApp","$uStorePath\WindowsServices","$uStorePath\DBBackup","$uStorePath\UpdateInstallApp","$uStoreSharedLocation\App_Data","$uStoreSharedLocation\Images","$uStoreSharedLocation\Skins","$uStoreSharedLocation\Themes")
		$uStoreLockedCount = 0
		foreach ($uStorePathCheck in $uStorePathsCheck) {
			if (Test-Path -Path $uStorePathCheck) {
				$uStoreBlockedFiles = ""
				$uStoreBlockedFiles = Get-ChildItem $uStorePathCheck -Recurse | Where-Object -FilterScript{[System.Security.Policy.Zone]::CreateFromUrl($_.FullName).SecurityZone -eq 'Internet'}
				$uStoreBlockedFilesString = "Get-ChildItem $uStorePathCheck -Recurse | Where-Object -FilterScript{[System.Security.Policy.Zone]::CreateFromUrl(`$_.FullName).SecurityZone -eq 'Internet'}"
				if ($uStoreBlockedFiles) {
					$uStoreLockedCount ++
					$ErrorCount++
					$BlockedFilesBackslashMessage = ""
					$BlockedFilesBackslashCheck = [Regex]::Matches($uStorePathCheck, "^\\\\")
					if ($BlockedFilesBackslashCheck) {
						$BlockedFilesBackslashMessage = "Notice: This specific path is a network path. In some cases, some servers will always indicate that the files are blocked, due to Internet security settings.`r`n"
					}
					wtf "There are files that are marked as blocked (downloaded from the internet)`r`nin the folder $uStorePathCheck" "" e "$BlockedFilesBackslashMessage You can see the blocked files using this command:`r`n$uStoreBlockedFilesString`r`n`r`nTo unblock these files, you can use the following command:`r`ndir -Path `"$uStorePathCheck`" -Recurse | Unblock-File"
				}
			}
		}
		if ($uStoreLockedCount -eq 0) {
			wtf "None of the files in the uStore folder are blocked" "" g
		}

		#are there any files starting with a dot in the folder root?
		#checking all folders may take too much time, so we are checking only the root as an indicator
		$uStoreDotCount = 0
		foreach ($uStorePathCheck in $uStorePathsCheck) {
			if (Test-Path "$uStorePathCheck\.*"  -PathType Leaf) {
				#starting from uStore 10 (or 11...) there are 2 dot files added to the CustomerApp folder, and we ignore them: .jshintrc and .weignore
				$uStoreDotFilesCustomerAppIgnore = ""
				if ($uStorePathCheck -eq "$uStorePath\CustomerApp") {
					$uStorePathCheckIgnore = 1
					$uStoreDotFilesCustomerAppIgnore = "`r`nThe following files are a part of the uStore installation, and ShOULD NOT be deleted: .jshintrc and .weignore"
					if (Test-Path "$uStorePathCheck\.*"  -PathType Leaf -exclude .jshintrc, .weignore) {
						$uStorePathCheckIgnore = 0
					}
				}
				if ($uStorePathCheckIgnore -ne 1) {
					$WarningCount++
					$uStoreDotCount ++
					$DotFilesuStoreFind = "Get-ChildItem -Path `"$uStorePathCheck`" -Filter `".*`" -Force -Recurse"
					#if it is a .DS_Store file, then we let the user know of its source
					if (Test-Path "$uStorePathCheck\.DS_Store"  -PathType Leaf) {
						#PS command given by Steve Case, to remove the nasty goblins!
						$DS_StoreSolutionGlobal = "Get-ChildItem -Path `"$uStorePathCheck`" -Filter `"*.DS_Store`" -Force -Recurse  | Remove-Item -Force"
						wtf "uStore: the folder $uStorePathCheck contains at least one file with a name that starts with a dot`r`n" "" w "This can cause problems, and such files should be cleared out of the application folder.`r`nOne of the files is .DS_Store and this file is created every time that a Mac user browses shared folders.`r`nFiles that are created in the XMPie folders should only be created by XMPie applications.`r`n`r`nTo delete all .DS_Store files from this folder, run the following command in PowerShell as an admin:`r`n$DS_StoreSolutionGlobal $uStoreDotFilesCustomerAppIgnore`r`n`r`nUse the following command to find all dot files in this folder:`r`n$DotFilesuStoreFind"
					}
					#if it is any other dot file, then we give a general warning
					else {
						wtf "uStore: the folder $uStorePathCheck contains at least one file with a name that starts with a dot`r`n" "" w "This can cause problems, and such files should be cleared out of the application folder.`r`nFiles that are created in the XMPie folders should only be created by XMPie applications.$uStoreDotFilesCustomerAppIgnore`r`n`r`nUse the following command to find all dot files in this folder:`r`n$DotFilesuStoreFind"
					}
				}
			}
			else {
				wtf "uStore: no files starting with a dot found in the root of the uStore folder $uStorePathCheck" "" g
			}
		}
		if ($uStoreDotCount -eq 0) {
			wtf "None of the files in the roots of uStore application folders start with a dot" "" g
		}

	}
	else {
		Write-Output "Could not find a uStore application path"
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nuStore application path not found in the system registry"
		}
		else {
			$ErrorCount++
			wtf "There is no uStore application path in the system registry" "" e
		}
	}
}

#combining the web.config files reporting for uProduce and uStore, in order to de-clutter the log after upgrade / modify / repair
if (($uProduceWebConfigModifiedCount -ne 0) -or ($uStoreWebConfigModifiedCount -ne 0)) {
	$XMPie_installed_recently_found = ""
	if ($uProduceWebConfigModifiedCount -eq 0) {
		wtf "None of the relevant web.config files in the uProduce folders were modified in the last $uProduceWebConfigModifiedDays days" "" g
	}
	else {
		$XMPie_installed_recently_found = "uProduce: There are web.config files that were changed in the last $uProduceWebConfigModifiedDays days:$uProduceWebConfigModifiedList`r`n"
	}

	if ($uStoreWebConfigModifiedCount -eq 0) {
		wtf "None of the relevant web.config files in the uStore folders were modified in the last $uStoreWebConfigModifiedDays days" "" g
	}
	else {
		$XMPie_installed_recently_found += "uStore: There are web.config files that were changed in the last $uStoreWebConfigModifiedDays days:$uStoreWebConfigModifiedList`r`n"
	}

	if ($XMPie_installed_recently_found) {
		if ($XMPie_installed_recently_disclaimer) {
			$NoticeCount++
			wtf "$XMPie_installed_recently_found" "" n "$XMPie_installed_recently_disclaimer"
		}
		else {
			$WarningCount++
			wtf "$XMPie_installed_recently_found" "" w
		}
	}
}





#check if IE enhanced security is enabled
#from:
#https://mvcp007.wordpress.com/2017/10/16/how-to-check-ie-enhanced-security-is-installed-windows-powershell/
function IECheckSecurity () {
	$ComputerName = $env:COMPUTERNAME
	$IEAdminRegistryKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
	$IEUserRegistryKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
	$KnownStatus = ""
	if ((Test-Path -Path $IEAdminRegistryKey) -or (Test-Path -Path $IEUserRegistryKey)) {
		$IEAdminRegistryValue = (Get-ItemProperty -Path $IEAdminRegistryKey -Name IsInstalled).IsInstalled
		if ($IEAdminRegistryKey -ne "" ) {
			if ($IEAdminRegistryValue -eq 0) {
				$KnownStatus = "Admins IE enhanced security is Disabled"
			}
			elseif ($IEAdminRegistryValue -eq 1) {
				$KnownStatus = "Admins IE enhanced security is Enabled"
			}
			else { 
				$KnownStatus = "Admins IE enhanced security is Unknown"
			}
		}
		$IEUserRegistryValue=(Get-ItemProperty -Path $IEUserRegistryKey -Name IsInstalled).IsInstalled
		if ($IEUserRegistryKey -ne "" ) {
			if ($IEUserRegistryValue -eq 0) {
				$KnownStatus = "$KnownStatus`r`nUsers IE enhanced security is Disabled"
			}
			elseif ($IEUserRegistryValue -eq 1) {
				$KnownStatus = "$KnownStatus`r`nUsers IE enhanced security is Enabled"
			}
			else { 
				$KnownStatus = "$KnownStatus`r`nUsers IE enhanced security is Unknown"
			}
		}
	}
	else {
		$KnownStatus = "IE enhanced security registry key is not found"
	}
	return $KnownStatus
}
Write-Output "Checking IE enhanced security status"
$IECheckSecurityStatus = IECheckSecurity
wtf "IE enhanced security status:" $IECheckSecurityStatus g


###begin licenses checks
Write-Output "Checking licenses"
#checking clicks, perpetual, Etc.
$SQLPerpetual = ""
if ($uProduceSQL) {
	$SQLPerpetual = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [CDKey],[Type],[Active],[Owner],[ActivationDate] FROM [XMPDB2].[XMPie].[TBL_LICENSE] WHERE Type='Perpetual'"
	if (!$SQLPerpetual) {
		#get the details of clicks, if such licenses exist in the License table
		$SQLClicks = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [CDKey],[Type],[Active],[Owner],[ActivationDate],[Value],[UsedValue],[Expiration] FROM [XMPDB2].[XMPie].[TBL_LICENSE] WHERE Type='VolumePack'" | Format-Table | out-string).Trim()
		$SQLClicksValid = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [CDKey],[Type],[Active],[Owner],[ActivationDate],[Value],[UsedValue],[Expiration] FROM [XMPDB2].[XMPie].[TBL_LICENSE] WHERE Type='VolumePack' and Expiration >= datediff(day, ActivationDate, getdate()) and Value > UsedValue" | Format-Table | out-string).Trim()
		#checking if the clicks are valid. If not, then notifying
		if ($SQLClicksValid) {
			wtf "There is at least one valid click license" $SQLClicksValid i
		}
		else {
		$ErrorCount++
			wtf "There is no valid click license, and the system does not have a perpetual license.`r`n`r`nCurrent license entries:" $SQLClicks e "Without any clicks license, the system cannot perform any production"
		}
	}
	else {
		#there is no real need to print out the actual perpetual license. commenting
		#wtf "System has a perpetual license" $SQLPerpetual i
		wtf "System has a perpetual license" "" g
	}
	
	#checking if the same license key has multiple occurences of the same type
	#for example: key 1111-2222-3333-4444 of type 'uImage Production' cannot exist more than once
	#
	#if we only wanted to show the CDKey and Type then this query would have been enough
	#$LicenseDuplicatesKeyType = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT CDKey, Type FROM [XMPie].[TBL_LICENSE] GROUP BY CDKey, Type HAVING COUNT(*) > 1"
	#but...
	#but we are greedy, hence the next query with more columns, curtesy of:
	#https://stackoverflow.com/a/11056306/722666
	$LicenseDuplicatesKeyType = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT A.ID, A.CDKey, A.Type, A.Owner, A.Active FROM [XMPie].[TBL_LICENSE] A INNER JOIN (SELECT CDKey, Type FROM [XMPie].[TBL_LICENSE] GROUP BY CDKey, Type HAVING COUNT(*) > 1) B ON A.CDKey = B.CDKey AND A.Type = B.Type" | Format-Table | out-string).Trim()
	if ($LicenseDuplicatesKeyType) {
		$WarningCount++
		wtf "There are multiple items for identical license keys with the same type:" $LicenseDuplicatesKeyType w "While this may not cause problems, it can indicate an underlying licensing issue"
	}
	else {
		wtf "No duplicate license entries with identical key and type found" "" g
	}

	#check if a server / extension has multiple keys of the same type. there is no reason for such a thing to exist
	$LicenseDuplicatesServer = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT A.ID, A.CDKey, A.Type, A.Owner, A.Active FROM [XMPie].[TBL_LICENSE] A INNER JOIN (SELECT Type, Owner FROM [XMPie].[TBL_LICENSE] GROUP BY Type, Owner HAVING COUNT(*) > 1) B ON A.Owner = B.Owner AND A.Type = B.Type" | Format-Table | out-string).Trim()
	if ($LicenseDuplicatesServer) {
		$WarningCount++
		wtf "A server / extension has multiple keys of the same type:" $LicenseDuplicatesServer w "While this should not cause problems, it can indicate an underlying licensing issue"
	}
	else {
		wtf "No duplicate keys of the same type found for a single server / extension" "" g
	}
}

#I know... I know... if uStore has its own SQL instance, then we're basically out of luck and we cannot check for the license
#so:
#if uStore is installed and we are on a director, then is there a 'uStore' item in the License table?
if (($Components -match "[r]") -and ($Components -match "[ad]")) {
	Write-Output "Checking uStore license"
	#$uStoreInstalled = SQLValue $uStoreSQL master "$DB_User" "$DB_Password" "SELECT * FROM sys.sysdatabases where name='uStore'"
	#if ($uStoreInstalled) {
		if (!$SQLLicenseuStore) {
			$ErrorCount++
			wtf "uStore license does not exist" "" e
		}
		else {
			wtf "uStore is licensed" "" g
		}
	#}
}


#and how about Windows OS activation check? why not?
#the result '1' should mean that the OS is activated
#however, it may be "licensed" but during an evaluation period. we are not checking that
Write-Output "Checking Windows activation"
$WindowsActivated = (Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object ApplicationId -EQ 55c92734-d682-4d71-983e-d6ec3f16059f | Where-Object PartialProductKey).LicenseStatus
switch ($WindowsActivated)
{
	"0" {$WindowsActivationStatus = "Unlicensed";}
	"1" {$WindowsActivationStatus = "Licensed";}
	"2" {$WindowsActivationStatus = "OOBGrace";}
	"3" {$WindowsActivationStatus = "OOTGrace";}
	"4" {$WindowsActivationStatus = "NonGenuineGrace";}
	"5" {$WindowsActivationStatus = "Notification";}
	"6" {$WindowsActivationStatus = "ExtendedGrace";}
	default {$WindowsActivationStatus = "Undetected";}
}
if ($WindowsActivated -eq 1) {
	wtf "Windows is activated. The activation status is $WindowsActivated which means: $WindowsActivationStatus" "" g
}
else {
	$WarningCount++
	wtf "Windows is not activated. The activation status is $WindowsActivated which means: $WindowsActivationStatus" "" w
}

###end licenses checks


#GDPR status in uProduce, and size of deleted jobs table
if ($uProduceSQL) {
	#do we have GDPR enabled? the value is 1 if we do
	$SQLGdprDsDeletion = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [pathValue] FROM [XMPDB2].[XMPie].[TBL_PATH_LOCATOR] where pathName = 'EnableGdprDsDeletion'"
	$SQLGdprJobDeletion = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [pathValue] FROM [XMPDB2].[XMPie].[TBL_PATH_LOCATOR] where pathName = 'EnableGdprJobDeletion'"
	#how many deleted jobs do we have?
	$SQLJobDeleted = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT count (1) FROM [XMPDB2].[XMPie].[TBL_JOB_DELETED]"
	#set a number to decide if we have "too many" deleted jobs
	$JobDeletedHigh = 100000
	if ($SQLJobDeleted -gt $JobDeletedHigh) {
		$JobDeletedGDPRRecommendation = ""
		$JobDeletedPerpetualMessage = ""
		if ($SQLGdprJobDeletion -ne 1) {
			$JobDeletedGDPRRecommendation = "`r`nGDPR Job Deletion is not enabled in this system. If it will be enabled, then it will also take care of removing old deleted jobs.`r`n"
		}
		if ($SQLPerpetual) {
			$JobDeletedPerpetualMessage = "`r`nThis specific system has a perpetual license, so the number of clicks is less relevant, however this is just one example and there is other data stored there."
		}
		$NoticeCount++
		$JobDeletedDELETEquery = "DELETE FROM [XMPDB2].[XMPie].[TBL_JOB_DELETED] WHERE jobSubmitTime <= DATEADD(day,-365,GETDATE())"
		wtf "Deleted jobs number is higher than $JobDeletedHigh`:" "$SQLJobDeleted`r`n" n "A high number of deleted jobs can cause the following table in the XMPDB2 database to become too big:`r`n[XMPie].[TBL_JOB_DELETED]`r`n$JobDeletedGDPRRecommendation`r`nIt is ok to delete records from this table. Just take into consideration that there is data in the jobs that will be deleted with them, such as how many clicks the specific job consumed.$JobDeletedPerpetualMessage`r`n`r`nYou can manually delete old entries from this table by running the following query. Replace the number 365 with the amount of days you want:`r`n$JobDeletedDELETEquery"
	}
	else {
		wtf "Deleted jobs number is lower than $JobDeletedHigh. Number of records: $SQLJobDeleted" "" g
	}
}


#checking UAC settings (user account control settings)
#rules and check from here:
#https://gallery.technet.microsoft.com/How-to-switch-UAC-level-0ac3ea11
Write-Output "Checking UAC settings"
$UACRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$UACConsentPromptBehaviorAdmin_Name = "ConsentPromptBehaviorAdmin"
$UACPromptOnSecureDesktop_Name = "PromptOnSecureDesktop"
$UACConsentPromptBehaviorAdmin_Value = RegKey $UACRegKey $UACConsentPromptBehaviorAdmin_Name
$UACPromptOnSecureDesktop_Value = RegKey $UACRegKey $UACPromptOnSecureDesktop_Name
$UACRecommendation = "UAC settings should be set to 'Never Notify'.`r`nThis setting can be changed by running the following executable:`r`nC:\Windows\System32\UserAccountControlSettings.exe"
If($UACConsentPromptBehaviorAdmin_Value -Eq 0 -And $UACPromptOnSecureDesktop_Value -Eq 0) {
	wtf "UAC settings are set to the recommended setting: `"Never notify`"" "" g
}
ElseIf($UACConsentPromptBehaviorAdmin_Value -Eq 5 -And $UACPromptOnSecureDesktop_Value -Eq 0) {
	$NoticeCount++	
	wtf "UAC settings (User Account Control Settings) are not set to the recommended setting. Current setting:" "Notify me only when apps try to make changes to my computer (do not dim my desktop)`r`n" n "$UACRecommendation"
}
ElseIf($UACConsentPromptBehaviorAdmin_Value -Eq 5 -And $UACPromptOnSecureDesktop_Value -Eq 1) {
	$NoticeCount++
	wtf "UAC settings (User Account Control Settings) are not set to the recommended setting. Current setting:" "Notify me only when apps try to make changes to my computer (default)`r`n" n "$UACRecommendation"
}
ElseIf($UACConsentPromptBehaviorAdmin_Value -Eq 2 -And $UACPromptOnSecureDesktop_Value -Eq 1) {
	$NoticeCount++
	wtf "UAC settings (User Account Control Settings) are not set to the recommended setting. Current setting:" "Always notify`r`n" n "$UACRecommendation"
}
Else {
	$NoticeCount++
	wtf "UAC settings (User Account Control Settings) are not set to the recommended setting. Current setting:" "Unknown`r`n" n "$UACRecommendation"
}


###begin reboot tests
#when was the last restart (reboot) in days
Write-Output "Checking when was the last restart (reboot)"
#if we want to get the actual date of the reboot, then this is the one:
$Reboot_Time=(Get-WmiObject win32_operatingsystem | Select-Object @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}).LastBootUpTime
function Get-Uptime{
      Param(
            $ComputerName = $env:COMPUTERNAME
       )

      if($c=Get-WmiObject win32_operatingsystem -ComputerName $ComputerName){
          $DaysSinceReboot=[datetime]::Now - $c.ConverttoDateTime($c.lastbootuptime) | findstr -i ^Days | ForEach-Object{($_ -split "\s+")[2]}
		  Write-Output $DaysSinceReboot
     }else{
          Write-Error "Unable to retrieve WMI Object win32_operatingsystem from $ComputerName"
     } 
}
#$Reboot_Days=$(Get-Uptime)
#the above, for some reason, stopped working. the following is from:
#https://4sysops.com/archives/calculating-system-uptime-with-powershell/
#$UptimeAll = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
#also did not work. now this:
#http://www.computerperformance.co.uk/powershell/powershell3-check-uptime.htm
$LastBooted = Get-WmiObject -Class Win32_OperatingSystem
$UptimeAll = [DateTime]::Now - $LastBooted.ConvertToDateTime($LastBooted.LastBootUpTime) 
$Reboot_Days = $UptimeAll.Days
$Reboot_Days = $Reboot_Days
if ($Days) {
	$Reboot_Days_to_Check=$Days
}
else {
	$Reboot_Days_to_Check=14
}
#check if the number of days since last reboot is smaller than or equal to the uptime
if ($Reboot_Days -le $Reboot_Days_to_Check) {
	$NoticeCount++
	$Reboot_Time_Log = ($Reboot_Time | out-string).Trim()
	wtf "Too little days since reboot (equal to or less than $Reboot_Days_to_Check days). Reboot time was:`r`n$Reboot_Time_Log`r`nDays since last reboot:" ($Reboot_Days | out-string).Trim() n
	# wtf "Date and time of last reboot" ($Reboot_Time | out-string).Trim() w
}
else {
	wtf "Date and time of last reboot" $Reboot_Time g
	wtf "Days since reboot" $Reboot_Days g
}


#check if a reboot is pending
Write-Output "Checking if a reboot is pending"
#Adapted from https://gist.github.com/altrive/5329377
#Based on <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542>
function Test-PendingReboot
{
 if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
 if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
 if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
 try { 
   $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
   $status = $util.DetermineIfRebootPending()
   if(($null -ne $status) -and $status.RebootPending){
     return $true
   }
 }catch{}
 
 return $false
}

$Reboot_Pending=Test-PendingReboot
if ($Reboot_Pending -eq $true) {
	$NoticeCount++
	wtf "The system is pending a reboot" "" n
}
else {
	wtf "The system is not pending a reboot" "" g
}

###end reboot tests



###begin SQL server and instance tests
#getting SQL instance settings
#https://www.red-gate.com/simple-talk/sql/sql-training/how-to-document-and-configure-sql-server-instance-settings/

#check if remote connections are allowed
#uProduce
if ($uProduceSQL) {
	Write-Output "uProduce: checking if SQL remote connections are allowed"
	$SQLRemoteAllowed = SQLProcess $uProduceSQL master "$DB_User" "$DB_Password" -sqlText "SELECT * FROM  sys.configurations where name like '%remote access%'"
	if ($SQLRemoteAllowed) {
		wtf "uProduce: SQL remote connections are allowed" "" g
	}
	else {
		$ErrorCount++
		wtf "uProduce: SQL remote connections are NOT allowed" "" e "This is a mandatory requirement for XMPie software to function properly"
	}
}
#uStore
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		Write-Output "uStore: checking if SQL remote connections are allowed"
		$SQLRemoteAllowed = SQLProcess $uStoreSQL master "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT * FROM  sys.configurations where name like '%remote access%'"
		if ($SQLRemoteAllowed) {
			wtf "uStore: SQL remote connections are allowed" "" g
		}
		else {
			$ErrorCount++
			wtf "uStore: SQL remote connections are NOT allowed" "" e
		}
	}
}

#SQL port + TCP/IP check
#for the TCP/IP tests we need an assembly that is not always loaded, so I am loading it here
#there is a nice function to check if an assembly is loaded, here:
#https://asaconsultant.blogspot.com/2014/09/powershell-get-loaded-assemblies.html
#[Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SqlWmiManagement') | out-null

#SQL port should be 1433. let's see if it is indeed that
#if not, then we will issue just a warning
#uProduce
#commenting this section, due to:
#1. too many systems produce an error due to permissions
#2. starting from PE 9.4, we anyway need either to have a running SQL Browse service, or state the specific port. so there is no reason for this check
# if ($uProduceSQL) {
if (1 -eq 2) {
	Write-Output "Checking SQL instance port 1433 + TCP/IP"
	#PORT test
	$SQLPortFounduProduce = ""
	$SQLPortFounduProduce = SQLProcess $uProduceSQL master "$DB_User" "$DB_Password" -sqlText "SELECT port FROM sys.dm_tcp_listener_states where port = 1433"
	#write-output $SQLPort
	if ($SQLPortFounduProduce) {
		wtf "uProduce SQL instance uses port 1433" "" g
	}
	else {
		$SQLPortFounduProduceFull1 = "SELECT * FROM sys.dm_tcp_listener_states"
		$SQLPortFounduProduceFull2 = SQLProcess $uProduceSQL master "$DB_User" "$DB_Password" -sqlText "SELECT * FROM sys.dm_tcp_listener_states"
		$SQLPortFounduProduceFull = -Join $SQLPortFounduProduceFull1, $SQLPortFounduProduceFull2
		#Write-Output $SQLPortFounduProduceFull
		$WarningCount++
		wtf "uProduce SQL instance does not use port 1433. Ports used:" $SQLPortFounduProduceFull w
	}
	#uProduce TCP/IP test
	#let's run this test on the director only. extensions show errors
	if ($Components -match "[ad]") {
		$uProduceWMI = New-Object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer')
		$uProduceWMIInstance = $uProduceWMI.ServerInstances | Where-Object { $_.Name -eq '$uProduceSQLSInstanceOnly' }
		$uProduceSQLTCP = $uProduceWMIInstance.ServerProtocols | Where-Object { $_.DisplayName -eq 'TCP/IP' }
		$uProduceSQLTCPDisabled = $uProduceSQLTCP | select-object 'DisplayName','IsEnabled' | Where-Object { !$_.IsEnabled } 
		if ($uProduceSQLTCPDisabled) {
			$ErrorCount++
			wtf "TCP/IP is disabled for the uProduce SQL instance" "" e
		}
		else {
			wtf "TCP/IP is enabled for the uProduce SQL instance" "" g
		}
	}
}


if ($uProduceSQL) {
	#in the case of uProduce, we also want to know that the SQL Browse service is running
	#it is not mandatory, but recommended, so warning only
	#relevant for PE 9.3.1 and above. uProduce build: 11070
	if ($uProduceBuild -and $uProduceBuild -ge 11070) {
		#relevant only if we are on an actual SQL server
		if ($Components -match "[s]") {
			Write-Output "Checking if SQL Browse service is running"
			$Service_SQLBrowser = Get-WmiObject win32_service -ErrorAction Stop | Where-Object {$_.Name -Like '*SQLBrowser*'} | Select-Object name,startname,state
			# Write-Output "Service_SQLBrowser is: $Service_SQLBrowser"
			#let's see if the service even exists
			if ($Service_SQLBrowser) {
				#check if there are any XMPie services that are NOT running
				$Service_SQLBrowser_Not_Running=($Service_SQLBrowser | Where-Object {$_.state -ne "Running"} | Format-Table | out-string)
				if ($Service_SQLBrowser_Not_Running) {
					$NoticeCount++
					wtf "SQL Browse service is not running" "" n "It is recommended to have SQL Browse service running for this version of uProduce"
				}
				else {
					wtf "SQL Browse service is up and running" "" g
				}
			}
			else {
				$NoticeCount++
				wtf "SQL Browse service does not exist" "" n "It is recommended to have SQL Browse service running for this version of uProduce"
			}
		}
		
		#for uProduce 9.3.1 and 9.4 - checking that the DotNet version is 4.7.2
		if (($uProduceBuild -eq 11070) -or ($uProduceBuild -eq 11208)) {
			Write-Output "Checking DotNet version"
			$DotNetReleaseRegPath = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
			$DotNetReleaseRegValue = RegKey $DotNetReleaseRegPath "Release"
			if (($DotNetReleaseRegValue -ne 461808) -and ($DotNetReleaseRegValue -ne 461814)) {
				$ErrorCount++
				wtf "uProduce version 9.3.1 and 9.4 require Microsoft DotNet version 4.7.2, but the value for that version is not found in the registry`r`n" "" e "Possible cause and solution:`r`nIt may be that the server was not restarted after uProduce installation. If so, then a restart is mandatory and may solve the issue.`r`n`r`nThe uProduce installer should have installed the correct version. It is either release 461808 or 461814.`r`n`r`nYou can find the value of the in the registry, in the following location (value of: Release):`r`nHKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
			}
			else {
				wtf "uProduce 9.3.1 or 9.4 is installed, and DotNet 4.7.2 is also installed" "" g
			}
		}
	}

	#uProduce 10 installer added an index, and the installer fails when there are duplicate records
	#so this test is relevant for uProduce 9.8.2 and below
	if ($uProduceBuild -and $uProduceBuild -le 12360) {
		$SQLDuplicateTouchpoints = SQLProcess $uProduceSQL master "$DB_User" "$DB_Password" -sqlText "SELECT tp.* FROM [XMPDB2].[XMPie].[TBL_TOUCHPOINT] tp JOIN (SELECT touchPointID, touchPointGUID, COUNT(*) as Qty FROM [XMPDB2].[XMPie].[TBL_TOUCHPOINT] GROUP BY touchPointID, touchPointGUID HAVING count(*) > 1 ) b ON tp.touchPointID = b.touchPointID AND tp.touchPointGUID = b.touchPointGUID ORDER BY tp.touchPointGUID"
		$SQLDuplicateTouchpointsQuery = "SELECT tp.*`r`nFROM [XMPDB2].[XMPie].[TBL_TOUCHPOINT] tp`r`nJOIN (SELECT touchPointID, touchPointGUID, COUNT(*) as Qty`r`nFROM [XMPDB2].[XMPie].[TBL_TOUCHPOINT]`r`nGROUP BY touchPointID, touchPointGUID`r`nHAVING count(*) > 1 ) b`r`nON tp.touchPointID = b.touchPointID`r`nAND tp.touchPointGUID = b.touchPointGUID`r`nORDER BY tp.touchPointGUID"
		if ($SQLDuplicateTouchpoints) {
			$WarningCount++
			wtf "There are dupicate touchpoint entries:" $SQLDuplicateTouchpoints w "uProduce installer from version 10 and above adds an index to the following table:`r`n[XMPDB2].[XMPie].[TBL_TOUCHPOINT]`r`n`r`nThis means that this system upgrade will fail, unless you get rid of the duplicates by deleting them.`r`n`r`nPlease consult XMPie R&D on how to proceed in this specific case.`r`n`r`nYou can view the full list of touchpoints using this query:`r`n$SQLDuplicateTouchpointsQuery"
		}
		else {
			wtf "There are no duplicate touchpoint entries in the [XMPDB2].[XMPie].[TBL_TOUCHPOINT] table" "" g
		}
	}
}


#checking for known problematic custom registry keys
#we check it in every configuration, since we only care about it if there are values in the location
Write-Output "Searching the custom registry keys"
$RegCustomLocations = @($Reg_uProduce_Location, $Reg_uProduce_Common)
#custom registry keys and their default values. add as many as you want
#we give the registry item with its default value
#TODO: deal with keys to which we do not have default values. since the only one I could find is RushJobsConfig, I am really not fussed by it
$RegCustomKeys = @(("NonOptimizedPDFLimit", 5), ("MaxThreads", -1), ("AutoSplitMerge_DisableByDefault", 0), ("uImagePhotoshopThreshold", 100), ("SeverityMask", 1))
$RegCustomFoundAmount = 0
$RegCustomFoundKeys = ""
foreach ($CustomLocation in $RegCustomLocations) {
	foreach ($CustomKey in $RegCustomKeys) {
		$RegCustomValue = ""
		$RegCustomValue = RegKey $CustomLocation $CustomKey[0]
		if ($RegCustomValue) {
			$CustomKeyName = $CustomKey[0]
			# $CustomKeyDefaultValue = $CustomKey[1]
			$RegCustomFoundAmount++
			if ($RegCustomFoundKeys) {
				$RegCustomFoundKeys +="`r`n"
			}
			$RegCustomFoundKeys += "`r`nKey found:   $CustomKeyName"
			$RegCustomFoundKeys += "`r`nValue found: $RegCustomValue"
			$RegCustomFoundKeys += "`r`nLocation:    $CustomLocation"
			#if we find a custom key that is using the default value, then we should rethink having it
			if ($RegCustomValue -eq $CustomKey[1]) {
				$RegCustomFoundKeys += "`r`nNOTE:`r`nThe value $RegCustomValue is the default value for this custom key. You may want to consider removing the key if it is not needed anymore"
			}
		}
	}
}
if ($RegCustomFoundKeys) {
	$NoticeCount++
	wtf "Custom registry keys found: $RegCustomFoundAmount. The keys are:" "$RegCustomFoundKeys" n
}
else {
	wtf "No custom registry keys found (not all keys are searched)" "" g
}


#uStore
if ($Components -match "[r]") {
	#cancelling the port 1433 and TCP/IP tests. too many problems with these ones.
	if (1 -eq 2) {
		$SQLPortFounduStore = ""
		$SQLPortFounduStore = SQLProcess $uStoreSQL master "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT port FROM sys.dm_tcp_listener_states where port = 1433"
		#write-output $SQLPort
		if ($SQLPortFounduStore) {
			wtf "uStore SQL instance uses port 1433" "" g
		}
		else {
			$SQLPortFounduStoreFull1 = "SELECT * FROM sys.dm_tcp_listener_states"
			$SQLPortFounduStoreFull2 = SQLProcess $uStoreSQL master "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT * FROM sys.dm_tcp_listener_states"
			$SQLPortFounduStoreFull = -Join $SQLPortFounduStoreFull1, $SQLPortFounduStoreFull2
			#Write-Output $SQLPortFounduStoreFull
			$WarningCount++
			wtf "uStore SQL does not use port 1433. Ports used:" $SQLPortFounduStoreFull w
		}
		
		#uStore TCP/IP test
		$uStoreWMI = New-Object ('Microsoft.SqlServer.Management.Smo.Wmi.ManagedComputer')
		$uStoreWMIInstance = $uStoreWMI.ServerInstances | Where-Object { $_.Name -eq '$uStoreSQLSInstanceOnly' }
		$uStoreSQLTCP = $uStoreWMIInstance.ServerProtocols | Where-Object { $_.DisplayName -eq 'TCP/IP' }
		$uStoreSQLTCPDisabled = $uStoreSQLTCP | select-object 'DisplayName','IsEnabled' | Where-Object { !$_.IsEnabled } 
		if ($uStoreSQLTCPDisabled) {
			$ErrorCount++
			wtf "TCP/IP is disabled for the uStore SQL instance" "" e
		}
		else {
			wtf "TCP/IP is enabled for the uStore SQL instance" "" g
		}
	}
}
###end SQL server and instance tests



###begin XMPie services tests
Write-Output "Checking XMPie services"

#TODO: validate this test. for now it will be Beta
if ($XMPiePath) {
	#in a uProduce server, there should be a service executable
	#I guess the most reliable check is if we have a path for XMPieExec in the registry. if we do, then we probably expect to have the service file in place
	$XMPServiceExecFile = Get-ChildItem "$XMPiePath\XMPService_*.exe" | Select-Object Name
	$XMPServiceExecFileCount = (Get-ChildItem "$XMPiePath\XMPService_*.exe" | Select-Object Name | measure-object).Count
	$XMPPlanServiceExecIssues = 0

	#there should not be a case when there is more than a single executable
	if ($XMPServiceExecFileCount -eq 0) {
		$ErrorCount++
		$XMPPlanServiceExecIssues++
		wtf "The XMPie service executable (XMPService_vXXXX.exe) was not found in the expected location:`r`n$XMPiePath" "" e
	}
	elseif ($XMPServiceExecFileCount -gt 0) {
		$XMPServiceExecFileNames = (Get-ChildItem "$XMPiePath\XMPService_*.exe").Name
		if ($XMPServiceExecFileCount -gt 1) {
			$WarningCount++
			$XMPPlanServiceExecIssues++
			wtf "There is more than a single XMPie service executable in the expected location.`r`n`r`nLocation:`r`n$XMPiePath`r`n`r`nFiles:" $XMPServiceExecFileNames w
		}
		elseif ($XMPServiceExecFileCount -eq 1) {
			wtf "There is a single XMPie service executable in the expected location:`r`n$XMPiePath`r`nFile:" $XMPServiceExecFileNames g
		}
	}

	#uProduce WSAPI should only have a single DLL file
	$XMPuProduceWSAPIFile = Get-ChildItem "$XMPiePath\XMPieWSAPI_*.dll" | Select-Object Name
	$XMPuProduceWSAPIFileCount = (Get-ChildItem "$XMPiePath\XMPieWSAPI_*.dll" | Select-Object Name | measure-object).Count
	$XMPPlanuProduceWSAPIIssues = 0

	#there should not be a case when there is more than a single DLL file
	if ($XMPuProduceWSAPIFileCount -eq 0) {
		$ErrorCount++
		$XMPPlanuProduceWSAPIIssues++
		wtf "The uProduce WSAPI DLL (XMPieWSAPI_vXXXX.dll) was not found in the expected location:`r`n$XMPiePath" "" e
	}
	elseif ($XMPuProduceWSAPIFileCount -gt 0) {
		$XMPuProduceWSAPIFileNames = (Get-ChildItem "$XMPiePath\XMPieWSAPI_*.dll").Name
		if ($XMPuProduceWSAPIFileCount -gt 1) {
			$WarningCount++
			$XMPPlanuProduceWSAPIIssues++
			wtf "There is more than a single uProduce WSAPI DLL in the expected location.`r`n`r`nLocation:`r`n$XMPiePath`r`n`r`nFiles:" $XMPuProduceWSAPIFileNames w
		}
		elseif ($XMPuProduceWSAPIFileCount -eq 1) {
			wtf "There is a single uProduce WSAPI DLL in the expected location:`r`n$XMPiePath`r`nFile:" $XMPuProduceWSAPIFileNames g
		}
	}

}

###
if ($Components -match "[x]") {
	$ServiceExistXLIM = ServiceSearch "XMPServiceXLIM"
	if (!$ServiceExistXLIM) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nXLIM service not found"
		}
		else {
			$ErrorCount++
			wtf "XLIM service expected but not found" "" e
		}
	}
}

if ($Components -match "[r]") {
	$ServiceExistuStoreACE = ServiceSearch "uStore.AceService"
	$ServiceExistuStoreOffice = ServiceSearch "uStore.OfficeService"
	$ServiceExistuStoreTask = ServiceSearch "uStore.TaskScheduler"
	$uStoreServicesExistReport = ""
	if (($ServiceExistuStoreACE) -or ($ServiceExistuStoreOffice) -or ($ServiceExistuStoreTask)) {
		$uStoreServicesExist = [Pscustomobject]@()
		$uStoreServicesExist += @{$ServiceExistuStoreACE.name = $ServiceExistuStoreACE.state} + @{$ServiceExistuStoreOffice.name = $ServiceExistuStoreOffice.state} + @{$ServiceExistuStoreTask.name = $ServiceExistuStoreTask.state}
		# $uStoreServicesExist += @{$ServiceExistuStoreACE.name = $ServiceExistuStoreACE.state}
		# $uStoreServicesExist += @{$ServiceExistuStoreOffice.name = $ServiceExistuStoreOffice.state}
		# $uStoreServicesExist += @{$ServiceExistuStoreTask.name = $ServiceExistuStoreTask.state}
		$uStoreServicesExistReport = ($uStoreServicesExist  | Format-Table | out-string)
	}
	if ((!$ServiceExistuStoreACE) -or (!$ServiceExistuStoreOffice) -or (!$ServiceExistuStoreTask)) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nuStore services (ACE or Office or Task Scheduler) not found:`r`n$uStoreServicesExistReport"
		}
		else {
			$ErrorCount++
			wtf "uStore services (ACE or Office or Task Scheduler) expected but not found:`r`n$uStoreServicesExistReport" "" e
		}
	}
}

if ($Components -match "[i]") {
	$ServiceExistINDD = ServiceSearch "XMPServiceINDD"
	if (!$ServiceExistINDD) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nInDesign service not found"
		}
		else {
			$ErrorCount++
			wtf "InDesign service expected but not found" "" e
		}
	}
}

if (($Components -match "[g]") -and ($uProduceBuild -and $uProduceBuild -lt 11070)) {
	$ServiceExistCopy = ServiceSearch "XMPServiceCOPY"
	if (!$ServiceExistCopy) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nuImage Copy service not found"
		}
		else {
			$ErrorCount++
			wtf "uImage Copy service expected but not found" "" e
		}
	}
}

if ($Components -match "[e]") {
	$ServiceExistEmail = ServiceSearch "XMPServiceEmail"
	if (!$ServiceExistEmail) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nEmail production service not found"
		}
		else {
			$ErrorCount++
			wtf "Email production service expected but not found" "" e
		}
	}
}

if ($Components -match "[c]") {
	if (!$ServiceExistCircle) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nCircle service not found"
		}
		else {
			$ErrorCount++
			wtf "Circle service expected but not found" "" e
		}
	}
}

if ($Components -match "[l]") {
	$ServiceExistSWF = ServiceSearch "XMPieServiceMngSWF"
	$ServiceExistSWFWorker = ServiceSearch "XMPieServiceMngSWF_Worker"
	if ((!$ServiceExistSWF) -or (!$ServiceExistSWFWorker)) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nXMPL services not found"
		}
		else {
			$ErrorCount++
			wtf "XMPL services expected but not found" "" e
		}
	}
}
#TODO: MC services. We will probably need to separate the MC components, as they have different services to check for


#get a list of all XMPie installed services
$Services_XMPie = Get-WmiObject win32_service -ErrorAction Stop | Where-Object {$_.Name -Like 'XMP*'} | Select-Object name,startname,state,StartMode
$Services_uStore = Get-WmiObject win32_service -ErrorAction Stop | Where-Object {$_.Name -Like 'uStore*'} | Select-Object name,startname,state,StartMode
$Services_XMPie_NoCircle_NoMC = (Get-WmiObject win32_service -ErrorAction Stop | Where-Object {$_.Name -Like 'XMP*' -and $_.Name -NotLike '*Circle Agent' -and $_.Name -NotLike 'XMPMCServer' -and $_.Name -NotLike 'XMPieProxyUpdaterServiceInstallCommand'} | Select-Object name,startname,state,StartMode | Format-Table | out-string)
#the following is the same as above, just keeping it as an object rather than a string
$Services_XMPie_NoCircle_NoMC_object = Get-WmiObject win32_service -ErrorAction Stop | Where-Object {$_.Name -Like 'XMP*' -and $_.Name -NotLike '*Circle Agent' -and $_.Name -NotLike 'XMPMCServer' -and $_.Name -NotLike 'XMPieProxyUpdaterServiceInstallCommand'} | Select-Object name,startname,state,StartMode
$Services_XMPie_and_uStore = Get-WmiObject win32_service -ErrorAction Stop | Where-Object {($_.Name -Like 'XMP*') -or ($_.Name -Like 'uStore*')} | Select-Object name,startname,state,StartMode
#in order to determine if we perform checks on uProduce and/or uStore service users, we first need to know if we have any
$CheckUser_uProduce = ""
$CheckUser_uStore = ""
#let's see if there are any XMPie services
#irrelevant if we are running the tool on an SQL server with nothing else on it
#for uImage only machines (UPU's), it is relevant for PE below 9.3.1 which is uProduce build 11070
if ((($Components -eq "g") -or ($Components -eq "wg") -or ($Components -eq "wtg")) -and ($uProduceBuild) -and ($uProduceBuild -ge 11070)) {
	[switch]$NewUPU = $true
}
else {
	[switch]$NewUPU = $false
}

if (($uProduceSQL) -and ($Components -ne "s") -and ($Components -ne "ws") -and (!$NewUPU)) {
#if (($uProduceSQL) -and ($Components -ne "s") -or ((($Components -ne "g") -and ($Components -ne "wg")) -and ($uProduceBuild) -and ($uProduceBuild -lt 11070))) {
	if ($Services_XMPie) {
		#there is a uProduce service user
		$CheckUser_uProduce = "y"
		
		#check if there are any XMPie services that are NOT set to start automatically
		$Services_XMPie_Not_Auto=($Services_XMPie | Where-Object {$_.StartMode -ne "Auto"} | Format-Table | out-string).Trim()
		if ($Services_XMPie_Not_Auto) {
			$ErrorCount++
			wtf "There are XMPie services that are not set to start automatically:" $Services_XMPie_Not_Auto e
		}
		else {
			wtf "All XMPie services are up and running" "" g
		}
		#check if there are any XMPie services that are NOT running
		$Services_XMPie_Not_Running=($Services_XMPie | Where-Object {$_.state -ne "Running"} | Format-Table | out-string).Trim()
		if ($Services_XMPie_Not_Running) {
			$ErrorCount++
			wtf "There are stopped XMPie services:" $Services_XMPie_Not_Running e
		}
		else {
			wtf "All XMPie services are up and running" "" g
		}

		#count the amount of unique 'run as user' that we have, not including Circle Agent and MC that are running using the LocalSystem account
		$Services_XMPie_users=($Services_XMPie_NoCircle_NoMC_object | Sort-Object -Unique startname).startname
		$Services_XMPie_users_count=($Services_XMPie_NoCircle_NoMC_object | Sort-Object -Unique startname | Measure-Object).Count
		#ideally, all services will run as the same user. let's see if that is the case
		if (($Services_XMPie_NoCircle_NoMC) -and ($Services_XMPie_users_count -eq 1)) {
			wtf "All XMPie services are running with the same user:" $Services_XMPie_users g
			#reporting the size of the user Temp directory
			#we are treating Services_XMPie_users as a single string, since we already verified that there is only a single object
			$Services_XMPie_users_string = $Services_XMPie_users| out-string
			$Services_XMPie_user_NoDomain_Array = ($Services_XMPie_users_string.Split('\')).Trim()
			$Services_XMPie_user_NoDomain = $Services_XMPie_user_NoDomain_Array[1]
			$Service_user_temp_folder = "C:\Users\$Services_XMPie_user_NoDomain\AppData\Local\Temp"
			if (Test-Path -Path "$Service_user_temp_folder") {
				[float]$Service_user_temp_space = Get-DirectorySizeWithRobocopy -folder "$Service_user_temp_folder" -units 'Mb'
				$TempVSFree = "Folder $Service_user_temp_folder`: $Service_user_temp_space mb`r`nDrive C free space: $DriveCFreeShow mb"
				$service_user_temp_del_command = "forfiles /P `"$Service_user_temp_folder`" /M `"*`" /S -C `"CMD /C DEL /F /Q @file`" /d -7"
				if ($Service_user_temp_space -gt $DriveCFreeSpaceHalf) {
					$WarningCount++
					wtf "The temporary files folder $Service_user_temp_folder is larger than half of the free space remaining in drive C" $TempVSFree w "You should consider deleting old temporary files using the following command in Powershell as an Administrator:`r`n$service_user_temp_del_command"
				}
				elseif ($XMPLogsSpace -gt 5000) {
					$NoticeCount++
					wtf "The temporary files folder $Service_user_temp_folder is very large: $Service_user_temp_space mb`r`n" "" n "Even though the temporary folder is still less than half of the free space in drive C:, you should consider deleting old temporary files using the following command in Powershell as an Administrator:`r`n$service_user_temp_del_command"
				}
				else {
					wtf "The size of the temporary files folder $Service_user_temp_folder is normal:" $TempVSFree g
				}
			}
			else {
				$NoticeCount++
				wtf "The XMPie service user ($Services_XMPie_users_string) temporary folder does not exist. Folder:" "$Service_user_temp_folder" n "It may be that this diagnostics tool does not recognize the folder properly. Usually it will happen if there is a local user and a domain user with the same name.`r`nIf you believe that this is the case, then please report this to the tool maintainer"
			}

			#TODO: check if the service user is a part of the administrators users group
			#can this even be done? the user can be a member of an AD group that is in the administrators, and we cannot know
			#there are 2 options here: bring all the groups of the user, or look for the user in the group
			#the following line brings all the groups of USER
			#Get-WmiObject win32_groupuser | Where-Object { $_.partcomponent -match 'name="USER"'} | Foreach-Object {[wmi]$_.groupcomponent}
			#the following line checks if USER is in the administrators users group. produces an error regarding my user when tested on my laptop. my user is a domain user, and it is not specified in the administrators group
			#gwmi win32_groupuser | ? groupcomponent -match 'administrators' | ? PartComponent -match 'Name="USER"' | % {[wmi]$_.partcomponent}
			#the same, in a different way. this one does not produce an error on my laptop (because it never does. it is not working as it should :-)
			#Get-CimInstance -ClassName win32_group -Filter "name = 'administrators'" | Get-CimAssociatedInstance -Association win32_groupuser | Where-Object { $_.Name -match 'USER' }
		}
		else {
			$WarningCount++
			wtf "XMPie services are defined with $Services_XMPie_users_count users:" "$Services_XMPie_NoCircle_NoMC" w
		}
		
	}
	else {
		#oops. there are NO XMPie services...
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nThere are no XMPie services defined"
		}
		else {
			$ErrorCount++
			wtf "There are no XMPie services defined" "" e
		}
	}
}

if ($Components -match "[r]") {
	#let's see if there are any uStore services
	if ($Services_uStore) {
		#there is a uStore service user
		$CheckUser_uStore = "y"

		#check if there are any uStore services that are NOT set to start automatically
		$Services_uStore_Not_Auto=($Services_uStore | Where-Object {$_.StartMode -ne "Auto"} | Format-Table | out-string).Trim()
		if ($Services_uStore_Not_Auto) {
			$ErrorCount++
			wtf "There are uStore services that are not set to start automatically:" $Services_uStore_Not_Auto e
		}
		else {
			wtf "All uStore services are up and running" "" g
		}
		#check if there are any uStore services that are NOT running
		$Services_uStore_Not_Running=($Services_uStore | Where-Object {$_.state -ne "Running"} | Format-Table | out-string).Trim()
		if ($Services_uStore_Not_Running) {
			$ErrorCount++
			wtf "There are stopped uStore services:" $Services_uStore_Not_Running e
		}
		else {
			wtf "All uStore services are up and running" "" g
		}

		#count the amount of unique 'run as user' that we have, not including Circle Agent and MC that are running using the LocalSystem account
		$Services_uStore_users=(($Services_uStore | Sort-Object -Unique startname).startname | Format-Table | out-string).Trim()
		$Services_uStore_users_count=($Services_uStore | Sort-Object -Unique startname | Measure-Object).Count
		#ideally, all services will run as the same user. let's see if that is the case
		if ($Services_uStore_users_count -eq 1) {
			wtf "All uStore services are running with the same user:" $Services_uStore_users g
			#TODO: check if the service user is a part of the administrators users group
			#there are 2 options here: bring all the groups of the user, or look for the user in the group
			#the following line brings all the groups of USER
			#Get-WmiObject win32_groupuser | Where-Object { $_.partcomponent -match 'name="USER"'} | Foreach-Object {[wmi]$_.groupcomponent}
			#the following line checks if USER is in the administrators users group. produces an error regarding my user when tested on my laptop. my user is a domain user, and it is not specified in the administrators group
			#gwmi win32_groupuser | ? groupcomponent -match 'administrators' | ? PartComponent -match 'Name="USER"' | % {[wmi]$_.partcomponent}
			#the same, in a different way. this one does not produce an error on my laptop
			#Get-CimInstance -ClassName win32_group -Filter "name = 'administrators'" | Get-CimAssociatedInstance -Association win32_groupuser | Where-Object { $_.Name -match 'USER' }
		}
		else {
			$WarningCount++
			wtf "uStore services are installed with $Services_uStore_users_count users:" "$Services_uStore_users" w
		}
		
	}
	else {
		#oops. there are NO uStore services...
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nThere are no uStore services installed"
		}
		else {
			$ErrorCount++
			wtf "There are no uStore services installed" "" e
		}
	}
}
#a general check to see if there are any services that are defined to start automatically, but have stopped abruptly
$ServicesCrashed = ""
$ServicesCrashed = (Get-wmiobject win32_service -Filter "startmode = 'auto' AND state != 'running' AND Exitcode !=0 " | Select-Object name, startname, exitcode | Format-Table | out-string).Trim()
if ($ServicesCrashed) {
	$WarningCount++
	wtf "There are crashed services that were marked to start automatically" $ServicesCrashed w
}
else {
	wtf "Did not find any crashed services amongst those that are marked to start automatically" "" g
}

###end XMPie services tests




###begin service users tests
#getting local users details, including the ones that need translating into human language
#from:
#https://mcpmag.com/articles/2015/04/15/reporting-on-local-accounts.aspx
Function Get-LocalUser  {
	[Cmdletbinding()]
	Param(
	[Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
	[String[]]$Computername =  $Env:Computername
	)

	Begin {
	#region  Helper Functions
		Function  ConvertTo-SID {
			Param([byte[]]$BinarySID)
			(New-Object  System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
		}

		Function  Convert-UserFlag {
			Param  ($UserFlag)
			$List  = New-Object  System.Collections.ArrayList
			Switch  ($UserFlag) {
				($UserFlag  -BOR 0x0001)  {[void]$List.Add('SCRIPT')}
				($UserFlag  -BOR 0x0002)  {[void]$List.Add('ACCOUNTDISABLE')}
				($UserFlag  -BOR 0x0008)  {[void]$List.Add('HOMEDIR_REQUIRED')}
				($UserFlag  -BOR 0x0010)  {[void]$List.Add('LOCKOUT')}
				($UserFlag  -BOR 0x0020)  {[void]$List.Add('PASSWD_NOTREQD')}
				($UserFlag  -BOR 0x0040)  {[void]$List.Add('PASSWD_CANT_CHANGE')}
				($UserFlag  -BOR 0x0080)  {[void]$List.Add('ENCRYPTED_TEXT_PWD_ALLOWED')}
				($UserFlag  -BOR 0x0100)  {[void]$List.Add('TEMP_DUPLICATE_ACCOUNT')}
				($UserFlag  -BOR 0x0200)  {[void]$List.Add('NORMAL_ACCOUNT')}
				($UserFlag  -BOR 0x0800)  {[void]$List.Add('INTERDOMAIN_TRUST_ACCOUNT')}
				($UserFlag  -BOR 0x1000)  {[void]$List.Add('WORKSTATION_TRUST_ACCOUNT')}
				($UserFlag  -BOR 0x2000)  {[void]$List.Add('SERVER_TRUST_ACCOUNT')}
				($UserFlag  -BOR 0x10000)  {[void]$List.Add('DONT_EXPIRE_PASSWORD')}
				($UserFlag  -BOR 0x20000)  {[void]$List.Add('MNS_LOGON_ACCOUNT')}
				($UserFlag  -BOR 0x40000)  {[void]$List.Add('SMARTCARD_REQUIRED')}
				($UserFlag  -BOR 0x80000)  {[void]$List.Add('TRUSTED_FOR_DELEGATION')}
				($UserFlag  -BOR 0x100000)  {[void]$List.Add('NOT_DELEGATED')}
				($UserFlag  -BOR 0x200000)  {[void]$List.Add('USE_DES_KEY_ONLY')}
				($UserFlag  -BOR 0x400000)  {[void]$List.Add('DONT_REQ_PREAUTH')}
				($UserFlag  -BOR 0x800000)  {[void]$List.Add('PASSWORD_EXPIRED')}
				($UserFlag  -BOR 0x1000000)  {[void]$List.Add('TRUSTED_TO_AUTH_FOR_DELEGATION')}
				($UserFlag  -BOR 0x04000000)  {[void]$List.Add('PARTIAL_SECRETS_ACCOUNT')}
			}
			$List  -join ', '
		}
	#endregion  Helper Functions
	}

	Process  {
		ForEach  ($Computer in  $Computername) {
		$adsi  = [ADSI]"WinNT://$Computername"
		$adsi.Children | Where-Object {$_.SchemaClassName -eq  'user'} |  ForEach-Object {
				[pscustomobject]@{
				UserName = $_.Name[0]
				SID = ConvertTo-SID -BinarySID $_.ObjectSID[0]
				PasswordAge = [math]::Round($_.PasswordAge[0]/86400)
				LastLogin = If ($_.LastLogin[0] -is [datetime]){$_.LastLogin[0]}Else{'Never logged  on'}
				UserFlags = Convert-UserFlag  -UserFlag $_.UserFlags[0]
				MinPasswordLength = $_.MinPasswordLength[0]
				MinPasswordAge = [math]::Round($_.MinPasswordAge[0]/86400)
				MaxPasswordAge = [math]::Round($_.MaxPasswordAge[0]/86400)
				BadPasswordAttempts = $_.BadPasswordAttempts[0]
				MaxBadPasswords = $_.MaxBadPasswordsAllowed[0]
				}
			}
		}
	}
}

#begin tests only if we have service users
if (($CheckUser_uProduce -eq "y") -or ($CheckUser_uStore -eq "y")) {
	Write-Output "Service users: checking if any LOCAL service users are set to have their password expired"
	foreach ( $TestLocalUserName in $Services_XMPie_users_uProduce_uStore ) {
		#Write-Output "CheckUser_uProduce $CheckUser_uProduce"
		# Grab the useraccount data
		#TODO: get a test that works. this test is never true, even when you change the user settings
		#$myLocalUser = [adsi]"WinNT://${env:computername}/$( $TestLocalUserName.Name )"
		#  Write-Output "password expiry test:"
		#  Write-Output $myLocalUser.UserFlags.value -band 65536
		#if ( ( $myLocalUser.UserFlags.value -band 66049 ) -eq 66049 ) {
		$TestLocalUserName = $TestLocalUserName -replace '\.\\'
		$TestedUserFlags = $Machine | Get-LocalUser | Where-Object {($_.UserName -eq $TestLocalUserName)} | Select-Object userflags
		if ($TestedUserFlags.userflags -Like "*DONT_EXPIRE_PASSWORD*") {
			wtf "The service user $TestLocalUserName is a local user, and the password is set to never expire" "" g
		}
		else {
			$ErrorCount++
			wtf "The following service user is a local user, and the password is set to expire:`r`n$TestLocalUserName" "" e
		}
	}
}
###end service users tests



###begin Circle Agent / XMPL Server checks
Write-Output "Circle Agent / XMPL Server tests"
#check if Circle Agent / XMPL Server are even installed
$CircleInstalled = ""
$XMPLInstalled = ""
#Circle Agent
if ($Components -match "[c]") {
	$CircleInstalled=$Installed_Software | findstr -i /C:"Circle.AgentInstaller" | Measure-Object -Line | Select-Object -expand Lines
	if ($CircleInstalled) {
		wtf "Circle Agent installation found" "" g
	}
	else {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nCircle Agent is not in the Windows programs list"
		}
		else {
			$ErrorCount++
			wtf "Are you sure that Circle Agent is installed? It is not in the Windows programs list" "" e
		}
	}
}
#XMPL Server
if ($Components -match "[l]") {
	$XMPLInstalled=$Installed_Software | findstr -i /C:"XMPL Server" | Measure-Object -Line | Select-Object -expand Lines
	if ($XMPLInstalled) {
		wtf "XMPL Server installation found" "" g
	}
	else {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nXMPL Server is not in the Windows programs list"
		}
		else {
			$ErrorCount++
			wtf "Are you sure that XMPL Server is installed? It is not in the Windows programs list" "" e
		}
	}
}

#Circle and XMPL 443 port accessiblity check
#check if Circle Agent or XMPL Server are installed, and then check if the ports are accessible
if ($Components -match "[cl]") {
	if (($CircleInstalled -gt 0) -or ($XMPLInstalled -gt 0)) {
		$PortsGood = @()
		$PortsBad = @()
		$URLSSL = @("eu.xmcircle.com","eu-west-1.queue.amazonaws.com","swf.eu-west-1.amazonaws.com")
		foreach ($SingleURL in $URLSSL) {
			# $SingleURL80 = "$SingleURL port 80"
			$SingleURL443 = "$SingleURL port 443"
			$Ports2G = New-Object Net.Sockets.TcpClient
			$Ports2G.Connect($SingleURL,443)
			if($Ports2G.Connected) {
				$PortsGood += $SingleURL443
			}
			else {
				$PortsBad += $SingleURL443
			}
			# $Ports2G80 = New-Object Net.Sockets.TcpClient
			#TODO: check if we actually need to check for port 80 as well. if so, then uncomment the following section and adjust the wtf to reflect that
			# $Ports2G80.Connect($SingleURL,80)
			# if($Ports2G80.Connected) {
				# $PortsGood += $SingleURL80
			# }
			# else {
				# $PortsBad += $SingleURL80
			# }
		}
		#if there are bad ports, then report an error. Otherwise just inform
		if ($PortsBad) {
			$ErrorCount++
			wtf "Outgoing port 443 is closed for the following Circle and XMPL addresses:" $PortsBad e
		}
		else {
			wtf "Outgoing port 443 is open for the following Circle and XMPL addresses:" $PortsGood g
		}
	}
}
###end Circle Agent / XMPL Server checks


#check if FIPS is enabled
Write-Output "Checking if FIPS is registered as enabled"
$FIPSFYI = "FYI, Microsoft stopped recommending enabling it. See here:`r`nhttps://blogs.technet.microsoft.com/secguide/2014/04/07/why-were-not-recommending-fips-mode-anymore/"
$FIPSRegPath =  "HKLM:\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy"
$FIPSRegValue = RegKey $FIPSRegPath "Enabled"
if ($FIPSRegValue -ne 1) {
	wtf "FIPS not registered as enabled in the registry" "" g
}
else {
	$NoticeCount++
	wtf "FIPS is registered as enabled in the registry.`r`n$FIPSFYI" "" n
}



###begin IIS Tests
#If IIS is installed, then go ahead
#TODO: check in which cases do we actually need IIS installed, and then test only in these cases
#until then, the only test is if IIS is installed, and not if it is needed
#for now (2019-06-23) we know that it IS needed on directors, and is NOT needed in extensions, so disabling the test in these cases
if (($Components -match "[xieg]") -and ($Components -NotMatch "[adlr]")) {
	Write-Output "IIS tests will not run on extensions, as IIS is not needed"
	wtf "IIS tests will not run on extensions, as it is not needed" "" g
}
else {
	$IIS_Installed=RegKey "HKLM:\SOFTWARE\Microsoft\InetStp" VersionString
	if ($IIS_Installed) {
		#IIS is installed, so check if IIS exists as a service, and go ahead
		$IIS_Service = get-wmiobject -query "select * from Win32_Service where name='W3svc'"
		If ($IIS_Service.Length -eq 0) {
			$ErrorCount++
			wtf "IIS is not installed as a service" "" e
		}
		Else {
			Write-Output "IIS is installed. Starting IIS checks"
			wtf "IIS service exists" "" g
			
			#is IIS running as a service?
			$IIS_Service_Running=($IIS_Service).State
			if ($IIS_Service_Running -eq "Running") {
				wtf "IIS service is running" "" g
			}
			else {
				$ErrorCount++
				wtf "IIS service is not running:" $IIS_Service e
			}

			#is there a web.config file in the main IIS folder?
			#getting the IIS default web site real location, from:
			#http://coderjony.com/blogs/get-physical-path-of-an-iis-website-using-powershell/
			[string] $iisWebsiteName = 'Default Web Site'
			$iisWebsite = Get-WebFilePath "IIS:\Sites\$iisWebsiteName"

			if($null -ne $iisWebsite)
			{
				$IISDefaultWebSiteFolder = $iisWebsite.FullName
				if ($IISDefaultWebSiteFolder -ne "C:\inetpub\wwwroot") {
					$NoticeCount++
					wtf "IIS Default Web Site location is not the default one. This is where you can find it:" "$IISDefaultWebSiteFolder" n
				}
				$IISConfFileFullPath = "$($IISDefaultWebSiteFolder)\web.config"
			}
			else {
				#if we fail to find a value for the default web site, then we go with the default
				$IISDefaultWebSiteFolder = "C:\inetpub\wwwroot"
				$IISConfFileFullPath = "$($IISDefaultWebSiteFolder)\web.config"
			}
			
			if (Test-Path -Path $IISConfFileFullPath) {
				$NoticeCount++
				wtf "A web.config file was found in the main IIS web site:" "$IISConfFileFullPath`r`n" n "While this should not necessarilly cause issues, you may want to have a look"

				#IIS web.config files modification time
				Write-Output "Checking if the default IIS web.config file was recently modified"
				if ($Days) {
					$IISWebConfigModifiedDays = $Days
				}
				else {
					$IISWebConfigModifiedDays = 30
				}
				$IISFileAge = Get-File-Modification-Age "$IISConfFileFullPath"
				if ($IISFileAge -lt $IISWebConfigModifiedDays) {
					$WarningCount++
					wtf "IIS: the general web.config file was changed in the last $IISWebConfigModifiedDays days." "$IISConfFileFullPath" w
				}
				else {
					wtf "IIS general web.config file was not modified in the last $IISWebConfigModifiedDays days" "" g
				}

				#TODO: decide if it even matters if the web.config file has more than X lines in it. for now - disabling this test
				#TODO: if you want to put the web.config contents in the log file, then notice that for some reason the line breaks are missing from the log file, so it appears as a single line
				#count the number of lines in the file. this one counts only the lines that are not empty
				if (1 -ne 1) {
					$IISConfFileLineCount = 0
					$IISConfFileLineCount = Get-Content $IISConfFileFullPath | Measure-Object -Line | Select-Object -expand Lines
					if ($IISConfFileLineCount -ne 0) {
						if ($IISConfFileLineCount -gt 10) {
							$NoticeCount++
							wtf "The web.config file was found in the main IIS web site, and it has more than 10 lines in it ($IISConfFileLineCount).`r`nFile location:`r`n" "$IISConfFileFullPath`r`n" n "While this should not necessarilly cause issues, you may want to have a look"
						}
						else {
							#contents of the file without empty lines
							# $IISConfFileContents = (Get-Content $IISConfFileFullPath) -notmatch '^\s*$'
							$NoticeCount++
							wtf "A web.config file was found in the main IIS web site, and it has $IISConfFileLineCount lines in it.`r`nFile location:`r`n" "$IISConfFileFullPath`r`n" n "While this should not necessarilly cause issues, you may want to have a look"
						}
					}
					else {
						$NoticeCount++
						wtf "There is a web.config file in the main IIS web site, and it is empty.`r`nYou may want to consider deleting it:`r`n" "$IISConfFileFullPath" n
					}
				}
			}
			else {
				wtf "A web.config file was not found in the main IIS web site" "" g
			}


			#the following tests will only work if the following role is installed:
			#Web Server > Management Tools > IIS Management Scripts and Tools
			$IISScriptsTools = FeatureInstalled Web-Scripting-Tools
			if ($IISScriptsTools -and $IISScriptsTools -ne "NA") {
				#getting all sites status (including FTP and what not)
				$IIS_sites=get-wmiobject -class Site -Authentication PacketPrivacy -Impersonation Impersonate -namespace "root/webadministration" | Select-Object name,ServerAutoStart
				$IIS_sites_stopped=$IIS_sites | Where-Object {$_.ServerAutoStart -eq $false}
				if ($IIS_sites_stopped) {
					$ErrorCount++
					wtf "IIS has some stopped sites:" $IIS_sites e
				}
				else {
					wtf "All IIS sites are up and running" "" g
				}
				
				#getting the list of all the application pools
				#$AppPools_list_all=gwmi -namespace "root\webadministration" -Class applicationpool | select name,AutoStart
				#get all application pools that are NOT running
				Write-Output "IIS: getting all applications pools that are not running"
				$AppPools_list_stopped=(Get-WmiObject -namespace "root\webadministration" -Class applicationpool | Where-Object {$_.AutoStart -eq $false} | Select-Object name,AutoStart | Format-Table | out-string).Trim()
				if ($AppPools_list_stopped) {
					$ErrorCount++
					wtf "there is at least one application pool that is not running" $AppPools_list_stopped e
				}
				else {
					wtf "All application pools are up and running" "" g
				}
				# Add-Type -Path ([Reflection.Assembly]::LoadWithPartialName("Microsoft.Web.Administration")).Location;
				# Add-Type -AssemblyName Microsoft.Web.Administration.ServerManager
				#the following is the only way that I could get the assembly to load in the EXE version of ServerStatus
				Add-Type -AssemblyName "Microsoft.Web.Administration, Version=7.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35, processorArchitecture=MSIL"

				#some application pools should not enable 32 bit applications
				#checking for XMPL Server API first
				#TODO: I found out that XMPL Server's API app pool is set to allow 32 bit apps in a new installation
				#on support case 00145719 Rafael and Edi told me that ti should be set to False
				#perhaps it was only in order to troubleshoot a specific installation, and it should not be checked at all

				#for now this test is disabled due to the above reasons. if enabling it, then put some content in the if and else below
				if (($Components -match "[l]") -and (1 -eq 2)) {
					if(Test-Path IIS:\AppPools\XMPieXMPL_REST_API) {
						$IISAppPoolXMPieXMPL_REST_API_32_bit_apps_True = Get-ItemProperty IIS:\AppPools\XMPieXMPL_REST_API | Where-Object {$_.enable32BitAppOnWin64 -like "*True*"}
						if ($IISAppPoolXMPieXMPL_REST_API_32_bit_apps_True) {
							f
						}
						else {
							d
						}
					}
					elseif ($Components -match "[z]") {
						$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nXMPL Server application pool XMPieXMPL_REST_API is not in the application pools list"
					}
					else {
						$ErrorCount++
						wtf "Are you sure that XMPL Server is installed? XMPL Server application pool XMPieXMPL_REST_API is not in the application pools list" "" e
					}
				}

				#XMPL Server: check if there is a binding for port 443
				if ($Components -match "[l]") {
					#if XMPL Server is not installed, then we don't report it here, since there is already a check for that above, so we just use $XMPLInstalled
					if ($XMPLInstalled) {
						#yes, we already have a check for port 80, however some sysadmins may want to get smart and use a custom port for SSL, so the check is for the string https
						#for the port test, look for Get-WebBinding in this file
						#the best advice for simply looking for https in the bindings, is to just search for the https string:
						#https://robwillis.info/2014/01/using-powershell-to-filter-and-sort-iis-binding-info/
						$SSLBindings = Get-ChildItem -Path IIS:\Sites | findstr "https"
						if ($SSLBindings) {
							wtf "XMPL Server: there is at least one SSL binding in IIS" "" g
						}
						else {
							wtf "XMPL Server does not have any https bindings in IIS" "`r`n" n "It is recommended to have at least one https binding for SSL in IIS"
						}
					}
				}
				
				#checking if there are any IIS SSL certificates that are about the expire in the near future
				if ($Days) {
					$SSLCertificatesExpiry_Days=$Days
				}
				else {
					$SSLCertificatesExpiry_Days=30
				}
				Write-Output "Checking if there are SSL certificates about to expire in the next $SSLCertificatesExpiry_Days days"
				$SSLExpiryGet = Get-ChildItem -Path cert: -Recurse -ExpiringInDays $SSLCertificatesExpiry_Days
				if ($SSLExpiryGet) {
					$WarningCount++
					wtf "There are SSL certificates about to expire in the next $SSLCertificatesExpiry_Days days:" "$SSLExpiryGet" w
				}
				else {
					wtf "There are no SSL certificates about to expire in the next $SSLCertificatesExpiry_Days days" "" g
				}


				#checking for custom HTTP Response Headers in the default web site
				#$iisWebsiteName is set above
				Write-Output "IIS: looking for custom HTTP Response Headers"
				# $IISManager = (New-Object -ComObject 'Microsoft.Web.Administration.ServerManager')
				$IISManager = new-object Microsoft.Web.Administration.ServerManager 
				$IISConfig = $IISManager.GetWebConfiguration($iisWebsiteName)
				$httpProtocolSection = $IISConfig.GetSection("system.webServer/httpProtocol") 
				$customHeadersCollection = $httpProtocolSection.GetCollection("customHeaders")
				$customHeadersCollection = ($httpProtocolSection.GetCollection("customHeaders")) | Select-Object -Property RawAttributes
				$customHeadersAtt = $customHeadersCollection.RawAttributes

				$CustomHeadersList = @()

				foreach ($CustomHeaderItem in $customHeadersAtt) {
					if (($CustomHeaderItem.name -ne "X-Powered-By") -and ($CustomHeaderItem.value -ne "ASP.NET")) {
						$CustomHeadersList += ([pscustomobject]@{Name=$CustomHeaderItem.name;Value=$CustomHeaderItem.value})
					}
				}

				if ($CustomHeadersList) {
					$WarningCount++
					$CustomHeadersCount = $CustomHeadersList.count
					$CustomHeadersListTable = ($CustomHeadersList | Format-Table | out-string).Trim()
					wtf "There are $CustomHeadersCount custom HTTP Response Headers in IIS `'$iisWebsiteName`':" "$CustomHeadersListTable`r`n" w "There should be only one name: `'X-Powered-By`' with the value `'ASP.NET`'.`r`nHaving customn values may interfere with general functionality of XMPie software, and in specific with uStore."
				}
				else {
					wtf "There are no relevant custom HTTP Response Headers in IIS `'$iisWebsiteName`'" "" g
				}

				Import-Module WebAdministration
			}
			elseif ($IISScriptsTools -eq "NA") {
				wtf "Cannot test web sites and application pools because the PowerShell Cmdlet Get-WindowsFeature does not exist. This is common in desktop systems" "" g
			}
			else {
				$NoticeCount++
				wtf "Cannot test web sites and application pools without the Windows role: IIS Management Scripts and Tools`r`n" "" n "You can install this role by running the following command in PowerShell as an admin user:`r`nInstall-Windowsfeature Web-Scripting-Tools"
			}
			
			#is there a binding for port 80?
			$Binding80 = Get-WebBinding | Where-Object {$_.bindingInformation -like "*:80:" -or $_.bindingInformation -like "*:80:*"}
			if (!$Binding80) {
				$ErrorCount++
				wtf "There is no binding to port 80 in any IIS web site" "" e
			}
			else {
				wtf "There is at least one binding to port 80 in IIS" "" g
			}
			
			#is the paramter 'Require SSL' enabled? if so, then there are a lot of possible issues
			$SSLRequired = (Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location 'Default Web Site/CertEnroll' -filter 'system.webServer/security/access' -name 'sslFlags').Value
			if ($SSLRequired -ne 0) {
				$WarningCount++
				wtf "SSL is marked as required in IIS for the Default Web Site.`r`n" "" w "This can cause issues with rewrite and redirect rules.`r`nSee the setting in the IIS Manager, under 'Default Web Site > SSL Settings'"
			}
			else {
				wtf "SSL is not marked as required for the Default Web Site" "" g
			}
			
			#are there any TLS used? If so, then which ones?
			#I used this for the matching table, and then ran all the possible combinations
			#http://www.keithtwombley.com/set-internet-options-via-the-registry/
			#TODO: I could not find a way of getting the values locally
			#remote tests tell me that marketing2 has TLS1.2, but locally I cannot find an evidence for it
			Write-Output "Checking which SSL/TLS are used by the server"
			$TLSRegPath =  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
			$TLSRegValue = "SecureProtocols"
			$TLSUsedReg = RegKey $TLSRegPath $TLSRegValue
			$TLSUsedRegTranslated = ""
			if ($TLSUsedReg) {
				switch ($TLSUsedReg) { 
					{$TLSUsedReg -eq 2048} {$TLSUsedRegTranslated = 'TLS 1.2'}
					{$TLSUsedReg -eq 512} {$TLSUsedRegTranslated = 'TLS 1.1'}
					{$TLSUsedReg -eq 2560} {$TLSUsedRegTranslated = 'TLS 1.1, TLS 1.2'}
					{$TLSUsedReg -eq 128} {$TLSUsedRegTranslated = 'TLS 1.0'}
					{$TLSUsedReg -eq 2176} {$TLSUsedRegTranslated = 'TLS 1.0, TLS 1.2'}
					{$TLSUsedReg -eq 640} {$TLSUsedRegTranslated = 'TLS 1.0, TLS 1.1'}
					{$TLSUsedReg -eq 2688} {$TLSUsedRegTranslated = 'TLS 1.0, TLS 1.1, TLS 1.2'}
					{$TLSUsedReg -eq 32} {$TLSUsedRegTranslated = 'SSL 3.0'}
					{$TLSUsedReg -eq 2080} {$TLSUsedRegTranslated = 'SSL 3.0, TLS 1.2'}
					{$TLSUsedReg -eq 544} {$TLSUsedRegTranslated = 'SSL 3.0, TLS 1.1'}
					{$TLSUsedReg -eq 2592} {$TLSUsedRegTranslated = 'SSL 3.0, TLS 1.1, TLS 1.2'}
					{$TLSUsedReg -eq 160} {$TLSUsedRegTranslated = 'SSL 3.0, TLS 1.0'}
					{$TLSUsedReg -eq 2208} {$TLSUsedRegTranslated = 'SSL 3.0, TLS 1.0, TLS 1.2'}
					{$TLSUsedReg -eq 672} {$TLSUsedRegTranslated = 'SSL 3.0, TLS 1.0, TLS 1.1'}
					{$TLSUsedReg -eq 2720} {$TLSUsedRegTranslated = 'SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2'}
					{$TLSUsedReg -eq 8} {$TLSUsedRegTranslated = 'SSL 2.0'}
					{$TLSUsedReg -eq 2056} {$TLSUsedRegTranslated = 'SSL 2.0, TLS 1.2'}
					{$TLSUsedReg -eq 520} {$TLSUsedRegTranslated = 'SSL 2.0, TLS 1.1'}
					{$TLSUsedReg -eq 2568} {$TLSUsedRegTranslated = 'SSL 2.0, TLS 1.1, TLS 1.2'}
					{$TLSUsedReg -eq 136} {$TLSUsedRegTranslated = 'SSL 2.0, TLS 1.0'}
					{$TLSUsedReg -eq 2184} {$TLSUsedRegTranslated = 'SSL 2.0, TLS 1.0, TLS 1.2'}
					{$TLSUsedReg -eq 648} {$TLSUsedRegTranslated = 'SSL 2.0, TLS 1.0, TLS 1.1'}
					{$TLSUsedReg -eq 2696} {$TLSUsedRegTranslated = 'SSL 2.0, TLS 1.0, TLS 1.1, TLS 1.2'}
					{$TLSUsedReg -eq 40} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0'}
					{$TLSUsedReg -eq 2088} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0, TLS 1.2'}
					{$TLSUsedReg -eq 552} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0, TLS 1.1'}
					{$TLSUsedReg -eq 2600} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0, TLS 1.1, TLS 1.2'}
					{$TLSUsedReg -eq 168} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0, TLS 1.0'}
					{$TLSUsedReg -eq 2216} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.2'}
					{$TLSUsedReg -eq 680} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1'}
					{$TLSUsedReg -eq 2728} {$TLSUsedRegTranslated = 'SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2'}
				}
				$TLSFindings = "Raw registry value: $TLSUsedReg`r`nThe value is translates to the following methods:`r`n$TLSUsedRegTranslated"
				wtf "(This test is BETA. Unreliable findings) SSL/TLS defined. The following methods are being used:" $TLSFindings i
			}
			else {
				$NoticeCount++
				wtf "(This test is BETA. Unreliable findings) SSL/TLS does not seem to be used in this server.`r`n" "" n "Look in the registry for the value of $TLSRegValue under the path:`r`n$TLSRegPath"
			}

			#this test and link are curtesy of Steve Lomax
			#https://techcommunity.microsoft.com/t5/iis-support-blog/centralized-certificate-store-ccs-and-iis-bindings/ba-p/582708
			# Look for Centralized Certificates (the XMPie software can't use them)
			$error.clear()
			try { Get-IISCentralCertProvider }
			catch {
				wtf "Centralized SSL Certificate Store is not enabled. This is good, since XMPie software cannot use it." "" g
			}
			if (!$error) {
				$ErrorCount++
				wtf "Centralized SSL Certificate Store is enabled." "" e "XMPie software does cannot use SSL certificates from a Centralized SSL Certificate Store.`r`nThis means that the certificates need to be installed locally if you wish to use them."
			}
		}
	}
	else {
		#hmm... Seems like IIS is not even installed. I better report it!
		$ErrorCount++
		wtf "IIS is not installed on this server" "" e
	}
	Write-Output "IIS tests complete"
}

###end IIS tests


###begin uProduce specific tests - uProduce tests - uProduce checks
if ($uProduceSQL) {
	#check for jobs in problematic statuses:
	Write-Output "uProduce: checking for jobs with a problematic status"
	#Waiting (1), In progress (2), Aborting (5)
	#or jobs stuck in the Message Queue table
	$JobsProblematicQueryNoLimit = "SELECT [jobID],[jobStatus],st.jobStatusName as Status,[jobSubmitTime],[jobStation],[outputType] FROM [XMPDB2].[XMPie].[TBL_JOB]`r`nleft join [XMPDB2].[XMPie].[TBL_REF_JOB_STATUS] st on st.jobStatusID = jobStatus`nwhere jobStatus=1 or jobStatus=2 or jobStatus=5"
	$JobsProblematicCount = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT count (1) FROM [XMPDB2].[XMPie].[TBL_JOB] where jobStatus=1 or jobStatus=2 or jobStatus=5"
	$JobsProblematic = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT top 20 [jobID],[jobStatus],st.jobStatusName as Status,[jobSubmitTime],[jobStation],[outputType] FROM [XMPDB2].[XMPie].[TBL_JOB] left join [XMPDB2].[XMPie].[TBL_REF_JOB_STATUS] st on st.jobStatusID = jobStatus where jobStatus=1 or jobStatus=2 or jobStatus=5" -| Format-Table | out-string).Trim()
	#checking if there are Aborting jobs in specific
	$JobsAbortingCount = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT count (1) FROM [XMPDB2].[XMPie].[TBL_JOB] where jobStatus=5"
	$JobsAbortingQuery = ""
	if ($JobsAbortingCount -gt 0) {
		$JobsAbortingList = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -format "values" -sqlText "SELECT jobID FROM [XMPDB2].[XMPie].[TBL_JOB] where jobStatus=5" | Format-Table | out-string).Trim()
		$JobsAbortingList = $($JobsAbortingList -split "`r`n").Trim()
		$JobsAbortingListUpdateQuery = ""
		foreach ($JobsAbortingItem in $JobsAbortingList) {
			#suggested by Amit Cohen: run a stored procedure for changing the status, rather than a simple UPDATE query
			$JobsAbortingListUpdateQuery = "$JobsAbortingListUpdateQuery`r`nEXEC [XMPDB2].[XMPie].[SP_JobSetStatus] @jobID = $JobsAbortingItem, @status = 6;"						
		}
		$JobsAbortingQuery = "There are ABORTING jobs`r`nTo change Aborting jobs to Aborted, you can use the following query:`r`n$JobsAbortingListUpdateQuery`r`n`r`n"
	}

	#checking if there are Waiting jobs in specific
	$JobsWaitingCount = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT count (1) FROM [XMPDB2].[XMPie].[TBL_JOB] where jobStatus=1"
	$JobsWaitingComment = ""
	if ($JobsWaitingCount -gt 0) {
		$JobsWaitingComment = "There are WAITING jobs`r`nWaiting jobs can sometimes be released by restarting the relevant XMPie service (XLIM, INDD, EMAIL).`r`nTo terminate Waiting jobs, you will need to Abort them from the uProduce Job Center or via the API.`r`n`r`n"
	}

	if ($JobsProblematic) {
		$WarningCount++
		wtf "$JobsProblematicCount problematic jobs found in uProduce.`r`n`r`nThe following statuses are checked:`r`nWaiting (ID 1)`r`nIn progress (ID 2)`r`nAborting (ID 3)`r`n`r`nStuck jobs (the following list is limited to 20 records):`r`n" "$JobsProblematic`r`n" w "$JobsAbortingQuery $JobsWaitingComment A query to get stuck jobs in the above statuses: `r`n$JobsProblematicQueryNoLimit"
	}
	else {
		wtf "No problematic jobs found in uProduce: Waiting, In Progress, Aborting" "" g
	}

	#checking for stuck jobs in the Message Queue table
	#TODO: add recommendations
	$JobsStuckQueryNoLimit = "SELECT [ID] ,[Label],[JobID],[QID],[NotSent],[CreationDate] FROM [XMPDB2].[XMPie].[TBL_QUEUE_MESSAGES]"
	$JobsStuck = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT TOP 20 [ID] ,[Label],[JobID],[QID],[NotSent],[CreationDate] FROM [XMPDB2].[XMPie].[TBL_QUEUE_MESSAGES]" | Format-Table | out-string).Trim()
	if ($JobsStuck) {
		$WarningCount++
		$JobsStuckCount = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT count (1) FROM [XMPDB2].[XMPie].[TBL_QUEUE_MESSAGES]"
		wtf "There are $JobsStuckCount jobs stuck in the message queue.`r`nStuck jobs (the following list is limited to 20 records):" "$JobsStuck`r`n" w "If you are about to truncate the table, then first make sure that there are no stuck jobs and stop all XMPie services. After truncating the table, restart the Message Queuing service.`r`nYou can use the following query to see if there are any stuck or active jobs:`r`n$JobsProblematicQueryNoLimit`r`n`r`nTo query for all the jobs stuck in the message queue table without limits: `r`n$JobsStuckQueryNoLimit"
	}
	else {
		wtf "There are no jobs stuck in the message queue" "" g
	}

	#TODO: decide if this test should even take place, since apparently the table keeps on ketting bloated and not all jobs messages are removed
	#checking for stuck messages in the Proxy Map table
	#stuck = older than 1 hour
	# $ProxyMsgsStuckQueryNoLimit = "SELECT [keyID],[keyType],[hostServer],[createdDate] FROM [XMPDB2].[XMPie].[TBL_PROXY_MAP] WHERE 1 <= datediff(hour, [createdDate], getdate())"
	# $ProxyMsgsStuck = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT TOP 20 [keyID],[keyType],[hostServer],[createdDate] FROM [XMPDB2].[XMPie].[TBL_PROXY_MAP] WHERE 1 <= datediff(hour, [createdDate], getdate())" | Format-Table | out-string).Trim()
	# if ($ProxyMsgsStuck) {
		# $WarningCount++
		# $ProxyMsgsStuckCount = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT count (*) FROM [XMPDB2].[XMPie].[TBL_PROXY_MAP] WHERE 1 <= datediff(hour, [createdDate], getdate())"
		# wtf "There are $ProxyMsgsStuckCount messages stuck in the Proxy Map table (older than 1 hour).`r`nSuch behavior should have been solved in PE 9.4.1. Please report it to XMPie RnD.`r`nQuery without limits: `r`n$ProxyMsgsStuckQueryNoLimit`r`nStuck messages (the following list is limited to 20 records):" $ProxyMsgsStuck w
	# }
	# else {
		# wtf "There are no messages stuck in the Proxy Map table" "" g
	# }


	#check if there are NULL values in the monitor tool. if there are, then there are duplicate and empty entries in the dashboard
	Write-Output "uProduce: checking for duplicate monitor tools"
	$MonitorToolNULLCount = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT count (*) FROM [XMPie].[TBL_MONITOR_SERVER_TOOL] WHERE PrivateParams IS NULL"
	if ($MonitorToolNULLCount -gt 0) {
		$NoticeCount++
		wtf "There are $MonitorToolNULLCount NULL entries in the monitor tools.`r`nThis causes double and empty objects in the uProduce dashboard Monitor section.`r`n" "" n "If you want to remove these entries, you can use the following query to backup the table and delete the entries:`r`n`r`nUSE XMPDB2`r`nGO`r`nSELECT * Into XMPie.TBL_MONITOR_SERVER_TOOL_BKP`r`nFROM XMPie.TBL_MONITOR_SERVER_TOOL`r`nGO`r`nDELETE FROM XMPie.TBL_MONITOR_SERVER_TOOL`r`nWHERE PrivateParams IS NULL"
	}
	else {
		wtf "Monitor tool has no NULL entries" "" g
	}

	#checking for File System assets sources with the Recursive option selected
	$uProduceAssetsRemoteRecursive = (SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "select top 20 act.accountID, aso.campaignID, aso.assetSourceID, act.accountName, cmp.campaignName, aso.assetSourceName, cast(aso.assetSourceParameters as xml).value('(/AssetSourceParameters/m_Params/AssetSourceParameter/m_Name)[3]', 'varchar(max)') AS Recursive, cast(aso.assetSourceParameters as xml).value('(/AssetSourceParameters/m_Params/AssetSourceParameter/m_Value)[3]', 'varchar(max)') AS RecursiveValue FROM [XMPDB2].[XMPie].[TBL_ASSET_SOURCE] aso left join [XMPDB2].[XMPie].[TBL_CAMPAIGN] cmp on cmp.campaignID=aso.campaignID left join [XMPDB2].[XMPie].[TBL_ACCOUNT] act on act.accountID=cmp.AccountID where assetSourceType in (2,3) and cmp.campaignID is not NULL and cast(aso.assetSourceParameters as xml).value('(/AssetSourceParameters/m_Params/AssetSourceParameter)[3]', 'varchar(max)') = 'DeepSearchTrue' order by act.accountID, cmp.campaignID" | Format-Table | out-string).Trim()
	if ($uProduceAssetsRemoteRecursive) {
		$NoticeCount++
		$uProduceAssetsRemoteRecursiveCount = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "select count(aso.assetSourceID) FROM [XMPDB2].[XMPie].[TBL_ASSET_SOURCE] aso left join [XMPDB2].[XMPie].[TBL_CAMPAIGN] cmp on cmp.campaignID=aso.campaignID left join [XMPDB2].[XMPie].[TBL_ACCOUNT] act on act.accountID=cmp.AccountID where assetSourceType in (2,3) and cmp.campaignID is not NULL and cast(aso.assetSourceParameters as xml).value('(/AssetSourceParameters/m_Params/AssetSourceParameter)[3]', 'varchar(max)') = 'DeepSearchTrue'"
		$uProduceAssetsRemoteRecursiveQueryFull = "select act.accountID, aso.campaignID, aso.assetSourceID, act.accountName, cmp.campaignName, aso.assetSourceName,`r`ncast(aso.assetSourceParameters as xml).value('(/AssetSourceParameters/m_Params/AssetSourceParameter/m_Name)[3]', 'varchar(max)') AS Recursive,`r`ncast(aso.assetSourceParameters as xml).value('(/AssetSourceParameters/m_Params/AssetSourceParameter/m_Value)[3]', 'varchar(max)') AS RecursiveValue`r`nFROM [XMPDB2].[XMPie].[TBL_ASSET_SOURCE] aso`r`nleft join [XMPDB2].[XMPie].[TBL_CAMPAIGN] cmp on cmp.campaignID=aso.campaignID`r`nleft join [XMPDB2].[XMPie].[TBL_ACCOUNT] act on act.accountID=cmp.AccountID`r`nwhere assetSourceType in (2,3) and cmp.campaignID is not NULL`r`nand cast(aso.assetSourceParameters as xml).value('(/AssetSourceParameters/m_Params/AssetSourceParameter)[3]', 'varchar(max)') = 'DeepSearchTrue'`r`norder by act.accountID, cmp.campaignID"
		$uProduceAssetsRemoteRecursiveMessageAmount = "The above list is limited to 20 records. To view the full list, use the following query:`r`n$uProduceAssetsRemoteRecursiveQueryFull "
		$uProduceAssetsRemoteRecursiveMessageDetails = "File system asset sources rely on the ways that different file systems check for recursive content.`r`nThis can cause great delays when producing.`r`nIt is recommended to either have all File System assets in a single folder, or separate the folders as different File System assets WITHOUT the Recursive option.`r`n`r`n$uProduceAssetsRemoteRecursiveMessageAmount"
		wtf "There are $uProduceAssetsRemoteRecursiveCount File System asset sources that have the Recursive option selected. (the following list is limited to 20 records):" "`r`n$uProduceAssetsRemoteRecursive`r`n" n "$uProduceAssetsRemoteRecursiveMessageDetails"
	}
	else {
		wtf "There are no File System asset sources that have the Recursive option selected" "" g
	}

}

###end uProduce specific tests



#uStore Garbage Collector checks
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		Write-Output "uStore: are there any failed scheduled or Garbage Collector tasks?"
		$uStoreGCFailed = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [TaskName],[LastRun],[LastError],[IsActive] FROM [uStore].[dbo].[TaskScheduler] where LastError != ''" | Format-Table | out-string).Trim()
		if ($uStoreGCFailed) {
			$ErrorCount++
			$uStoreGCFailedCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT count (*) FROM [uStore].[dbo].[TaskScheduler] where LastError != ''"
			wtf "uStore: there are $uStoreGCFailedCount scheduled or Garbage Collector tasks that did not end successfully:" $uStoreGCFailed e
		}
		else {
			wtf "uStore: all scheduled or Garbage Collector tasks ended successfully" "" g
		}
		Write-Output "uStore: are all scheduled or Garbage Collector tasks active?"
		$uStoreGCNotActive = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [TaskName],[LastRun],[LastError],[IsActive] FROM [uStore].[dbo].[TaskScheduler] where IsActive != '1'" | Format-Table | out-string).Trim()
		if ($uStoreGCNotActive) {
			$WarningCount++
			$uStoreGCNotActiveCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT count (*) FROM [uStore].[dbo].[TaskScheduler] where IsActive != '1'"
			wtf "uStore: there are $uStoreGCNotActiveCount scheduled or Garbage Collector tasks that are not active:" $uStoreGCNotActive w
		}
		else {
			wtf "uStore: all scheduled or Garbage Collector tasks are active" "" g
		}
	}
}

#uStore Mall settings checks
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		#the 'uStore Server IP' should not be localhost or 127.0.0.1 since uStore needs to be visible for other servers, such as FFC
		Write-Output "uStore: is the uStore Server IP in Mall settings defined as a real address?"
		$uStoreMallServerIP = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [UStoreServerIP] FROM [uStore].[dbo].[Mall] where UStoreServerIP in ('localhost', '10.1.1.127')"
		if ($uStoreMallServerIP) {
			$ErrorCount++
			wtf "uStore: the uStore Server IP in Mall Settings is not set up correctly. Current value:" "$uStoreMallServerIP`r`n" e "There are other services, such as FreeFlow Core, that use this setting, and if it an address that they cannot resolve then some functions will not work properly.`r`n`r`nIn order to fix this, please go to 'Presets > System Setup > Mall'.`r`nThere, edit the value of 'uStore Server IP' to a real value, such as the real IP address or a name that can be resolved from other relevant servers.`r`n`r`nSuggested values are the internal IP address or the machine name (hostname):`r`nInternal server IP: $($IP_Local_output.ipaddress)`r`nMachine name: $Machine"
		}
		else {
			wtf "uStore: the uStore Server IP is not set with the localhost address. Value:" "$uStoreMallServerIP" g
		}

		#mail sending from stores will not work in the following case:
		#there is no SMTP provider defined AND there is no uProduce delivery provider selected
		Write-Output "uStore: are there stores without a delivery provider?"
		$uStoreMallSMTP = (SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [SMTPServer] FROM [uStore].[dbo].[Mall]" | out-string).Trim()
		if ($uStoreMallSMTP -ne "") {
			wtf "uStore: there is an SMTP email server defined in the uStore Mall settings: $uStoreMallSMTP" "" g
		}
		else  {
			#if there is no general SMTP defined in uStore, then we need to check if all online stores are set up
			$uStoreActiveStoresNoEmail = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [StoreID] from [uStore].[dbo].[Store] where [StatusID] = 1 and [EmailProviderID] is NULL" | Format-Table | out-string).Trim()
			if ($uStoreActiveStoresNoEmail) {
				$WarningCount++
				wtf "uStore: there are online stores that cannot send email messages:" "$uStoreActiveStoresNoEmail`r`n" w "Notifications cannot be sent from these stores.`r`n`r`nReason: uStore does not have an SMTP server defined, and these stores are online and are not using any uProduce delivery provider.`r`n`r`nYou can fix that by either selecting a uProduce delivery provider in the stores settings (Advanced > Email Provider),`r`nor by setting an SMTP server in uStore: Presets > System Setup > Mall"				
			}
			else {
				wtf "uStore: there is no SMTP email server defined in uStore, but all online stores have a uProduce provider defined" "" g
			}
		}
	}
}


#uStore checks for duplicate users (have the same user name AND email address)
#TODO: activate again once we know how to deal with users that are registered in multiple stores. See SF KB for more details
if (($Components -match "[r]") -and (1 -eq 2)) {
# if ($Components -match "[r]") {
	if ($uStoreSQL) {
		Write-Output "uStore: check for duplicate users"
		$uStoreDuplicateUsers = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT TOP 20 Login, Email, COUNT(*) as 'Records' FROM users where StatusID=1 GROUP BY Login, Email HAVING COUNT(*) > 1" | Format-Table | out-string).Trim()
		Write-Output $uStoreDuplicateUsers
		exit
		if ($uStoreDuplicateUsers) {
			$WarningCount++
			$uStoreDuplicateUsersCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT count(*) FROM (SELECT Login, Email, COUNT(*) as 'Records' FROM users where StatusID=1 GROUP BY Login, Email HAVING COUNT(*) > 1) duplicates"
			$uStoreDuplicateUsersText = $uStoreDuplicateUsers | Out-String
			$uStoreDuplicateUsersFind = "SELECT Login, Email, COUNT(*) as 'Records' FROM users where StatusID=1 GROUP BY Login, Email HAVING COUNT(*) > 1"
			wtf "uStore: there are $uStoreDuplicateUsersCount duplicate users (the following list is limited to 20 records):`r`n$uStoreDuplicateUsersText`r`n" "" w "You can find them in the uStore DB using this query:`r`n$uStoreDuplicateUsersFind`r`n`r`nIf you want to fix this, then edit the redundant users and change their email addresses,`r`nin order to leave just one user with the email address"
		}
		else {
			wtf "uStore: there are no duplicate users" "" g
		}
	}
}

#uStore checks for Order Handling Status
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		#uStore checks for duplicate Order Handling Status Category
		#there should not be a reason to create a duplicate category, and the customer should consider removing one of the categories
		Write-Output "uStore: check for duplicate users"
		$uStoreDuplicateOrderHandlingStatus = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT top 20 w.WorkflowOrderHandlingStatusID ,f.Name as Category ,h.Name as OrderHandlingStatus ,w.WorkflowID as CategoryID ,w.OrderHandlingStatusID from WorkflowOrderHandlingStatus w join (select WorkflowID, OrderHandlingStatusID from WorkflowOrderHandlingStatus group by WorkflowID, OrderHandlingStatusID having count(*) > 1 ) b on w.WorkflowID = b.WorkflowID and w.OrderHandlingStatusID = b.OrderHandlingStatusID left join [uStore].[dbo].[OrderHandlingStatus] h on h.OrderHandlingStatusID=w.OrderHandlingStatusID left join [uStore].[dbo].[OrderWorkflow] f on f.WorkflowID=w.WorkflowID" | Format-Table | out-string).Trim()
		if ($uStoreDuplicateOrderHandlingStatus) {
			$WarningCount++
			$uStoreDuplicateOrderHandlingStatusCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT count(*) FROM (SELECT w.WorkflowOrderHandlingStatusID ,f.Name as Category ,h.Name as OrderHandlingStatus ,w.WorkflowID as CategoryID ,w.OrderHandlingStatusID from WorkflowOrderHandlingStatus w join (select WorkflowID, OrderHandlingStatusID from WorkflowOrderHandlingStatus group by WorkflowID, OrderHandlingStatusID having count(*) > 1 ) b on w.WorkflowID = b.WorkflowID and w.OrderHandlingStatusID = b.OrderHandlingStatusID left join [uStore].[dbo].[OrderHandlingStatus] h on h.OrderHandlingStatusID=w.OrderHandlingStatusID left join [uStore].[dbo].[OrderWorkflow] f on f.WorkflowID=w.WorkflowID) duplicates"
			$uStoreDuplicateOrderHandlingStatusText = $uStoreDuplicateOrderHandlingStatus | Out-String
			$uStoreDuplicateOrderHandlingStatusFind = " SELECT w.WorkflowOrderHandlingStatusID ,f.Name as Category ,h.Name as OrderHandlingStatus ,w.WorkflowID as CategoryID ,w.OrderHandlingStatusID`r`n from WorkflowOrderHandlingStatus w`r`n join (select WorkflowID, OrderHandlingStatusID from WorkflowOrderHandlingStatus`r`n group by WorkflowID, OrderHandlingStatusID having count(*) > 1 ) b`r`n on w.WorkflowID = b.WorkflowID and w.OrderHandlingStatusID = b.OrderHandlingStatusID`r`n left join [uStore].[dbo].[OrderHandlingStatus] h on h.OrderHandlingStatusID=w.OrderHandlingStatusID`r`n left join [uStore].[dbo].[OrderWorkflow] f on f.WorkflowID=w.WorkflowID"
			wtf "uStore: there are $uStoreDuplicateOrderHandlingStatusCount duplicate Order Handling Status categories (the following list is limited to 20 records):`r`n$uStoreDuplicateOrderHandlingStatusText`r`n" "" w "You can find them in the uStore DB using this query:`r`n$uStoreDuplicateOrderHandlingStatusFind`r`n`r`nIf you want to fix this, then delete the redundant categories (there should not be a need to create duplicate categories)"
		}
		else {
			wtf "uStore: there are no duplicate Order Handling Status categories" "" g
		}
		
		#uStore checks for Order Handling Status without any localization values
		Write-Output "uStore: check for Order Handling Status with no localization values"
		$uStoreOrderHandlingStatusLocalization = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT OH.[OrderHandlingStatusID], OH.[Name], OH.[Description], OH.[DisplayName] FROM [uStore].[dbo].[OrderHandlingStatus] OH left join [uStore].[dbo].[OrderHandlingStatus_Culture] SC on SC.OrderHandlingStatusId=OH.OrderHandlingStatusID where SC.OrderHandlingStatusId is NULL" | Format-Table | out-string).Trim()
		if ($uStoreOrderHandlingStatusLocalization) {
			$WarningCount++
			$uStoreOrderHandlingStatusLocalizationCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT count (1) FROM [uStore].[dbo].[OrderHandlingStatus] OH left join [uStore].[dbo].[OrderHandlingStatus_Culture] SC on SC.OrderHandlingStatusId=OH.OrderHandlingStatusID where SC.OrderHandlingStatusId is NULL"
			wtf "uStore: there are $uStoreOrderHandlingStatusLocalizationCount Order Handling Status items without ANY localization values to them:`r`n$uStoreOrderHandlingStatusLocalization`r`n" "" w "These items can cause errors in various screens.`r`n`r`nThe solution should be to add at least a single localization to these items, by going to 'Presets > System Setup > Order Handling Status'.`r`nThere, click on View for the relevant Order Handling Status ID, then click 'Edit Localized Text' and 'Add New'."
		}
		else {
			wtf "uStore: all Order Handling Status items have at least a single localization value to them" "" g
		}

		#uStore checks Global Property 'Color' that has a custom value
		###
		if (1 -eq 2) {
			Write-Output "uStore: check if the 'Color' Global Property that has a custom value"
			$uStoreGlobalPropertyColor = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [FieldOptionID] FROM [uStore].[dbo].[FieldOption] where DialID=2 and FieldOptionID > 9999" | Format-Table | out-string).Trim()
			if ($uStoreGlobalPropertyColor) {
				$NoticeCount++
				$uStoreGlobalPropertyColorCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT count(1) FROM [uStore].[dbo].[FieldOption] where DialID=2 and FieldOptionID > 9999"
				wtf "uStore: there are $uStoreGlobalPropertyColorCount Additional values to the 'Color' Global Property." "" n "These items can cause ALL products that are using this property to stop working.`r`n`r`nThe solution should be to remove the additional values, and create custom properties that will have any desired values.`r`nThis can be done under 'Presets > Global Product Properties Setup'.`r`nThere, edit the Color property and make it has only True and/or False as values, and afterwards you can add new custom properties."
			}
			else {
				wtf "uStore: the 'Color' Global Property has only valid values" "" g
			}
		}
	}
}


#uStore checks for Excel Pricing provider. It should be SmartXLS
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		Write-Output "uStore: check for Excel Pricing provider"
		$uStoreMessageTemplateXMLFormatExists = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "select mtc.MessageTemplateCultureId from MessageTemplate_Culture mtc join MessageTemplate mt on mt.MessageTemplateId = mtc.MessageTemplateId where mtc.MessageBody like '%OrderDetails.aspx%' and mt.EventKeyPointId in (4,12,14,15) and TRY_CAST(mtc.MessageBody as xml) is null"
		if ($uStoreMessageTemplateXMLFormatExists) {
			$WarningCount++
			$uStoreMessageTemplateXMLFormat = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "select mtc.MessageTemplateCultureId, mt.Name, mtc.CultureId, mtc.MessageBody, mt.MessageTemplateId from MessageTemplate_Culture mtc join MessageTemplate mt on mt.MessageTemplateId = mtc.MessageTemplateId where mtc.MessageBody like '%OrderDetails.aspx%' and mt.EventKeyPointId in (4,12,14,15) and TRY_CAST(mtc.MessageBody as xml) is null" | Format-Table | out-string).Trim()
			wtf "uStore: there are localized Message Templates that have XML that is not formatted well:" "$uStoreMessageTemplateXMLFormat`r`n" w "You should tell the uStore operator to check these localized messages and correct their format.`r`nMalformed XML can cause failures when running the uStore installer (during upgrade / modify / repair).`r`n`r`nThe most common reason is that there is a specific UTF definition in the header. Once it is removed the error is gone. For example:`r`n<?xml version=`"1.0`" encoding=`"utf-8`"?>`r`n`r`nYou can use an online XML validator such as this one in order to check and validate the XML:`r`nhttps://codebeautify.org/xmlvalidator"
		}
		else {
			wtf "uStore: localized Message Templates seem to have well formed XML (relevant for installer checks only)" "" g
		}
	}
}


#uStore checks for localized message templates that have malformed XML
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		Write-Output "uStore: check for Message Templates localizations with malformed XML"
		$ExcelProvider = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT [Value] FROM [uStore].[dbo].[Config] where name = 'ExcelProvider' and Value != 'SmartXls'"
		if ($ExcelProvider) {
			$NoticeCount++
			wtf "uStore: Excel Pricing provider is not SmartXls, and this can cause severe performance and licensing issues.`r`nCurrent provider: $ExcelProvider`r`n" "" n "You should consider using SmartXls as the provider, ONLY after consulting with the end client,`r`nsince the reasons for using another provider may still be relevant."
		}
		else {
			wtf "uStore: Excel Pricing provider is SmartXls" "" g
		}
	}
}


#uStore check for uStoreShared folder
if ($Components -match "[r]") {
	Write-Output "uStore: shared folder tests"
	#relevant only if we can find the shared folder location in the registry
	if (!$uStoreSharedLocation) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nuStore shared folder location not found in the registry"
		}
		else {
			$ErrorCount++
			wtf "uStore shared folder location not found in the system registry" "" e
		}
	}
	else {
		#let's see if the path even exists...
		if (Test-Path -Path $uStoreSharedLocation) {
			#are there any files starting with a dot in the folder root?
			#checking all folders may take too much time, so we are checking only the root as an indicator
			if (Test-Path "$uStoreSharedLocation\.*"  -PathType Leaf) {
				$WarningCount++
				$DotFilesuStoreSharedFind = "Get-ChildItem -Path `"$uStoreSharedLocation`" -Filter `".*`" -Force -Recurse"
				#if it is a .DS_Store file, then we let the user know of its source
				if (Test-Path "$uStoreSharedLocation\.DS_Store"  -PathType Leaf) {
					$DS_StoreSolutionShared = "Get-ChildItem -Path `"$uStoreSharedLocation`" -Filter `"*.DS_Store`" -Force -Recurse  | Remove-Item -Force"
					wtf "uStore: the shared folder contains at least one file with a name that starts with a dot.`r`nThis can cause problems, and such files should be cleared out of the shared folder.`r`nOne of the files is .DS_Store and this file is created every time that a Mac user browses shared folders.`r`nFiles that are created in the XMPie folders should only be created by XMPie applications.`r`nuStore shared folder location: $uStoreSharedLocation`r`n" "" w "To delete all .DS_Store files from this folder, run the following command in PowerShell as an admin:`r`n$DS_StoreSolutionShared`r`nUse the following command to find all dot files in this folder:`r`n$DotFilesuStoreSharedFind"
				}
				#if it any other dot file, then we give a general notice
				else {
					wtf "uStore: the shared folder contains at least one file with a name that starts with a dot.`r`nThis can cause problems, and such files should be cleared out of the shared folder.`r`nFiles that are created in the XMPie folders should only be created by XMPie applications.`r`nuStore shared folder location:`r`n$uStoreSharedLocation`r`n" "" w "Use the following command to find all dot files in this folder:`r`n$DotFilesuStoreSharedFind"
				}
			}
			else {
				wtf "uStore: no files starting with a dot found in the root of the uStoreShared folder" "" g
			}
		}
		else {
			$ErrorCount++
			wtf "uStore shared folder not found in the expected location:" "$uStoreSharedLocation" e
		}
	}
}


#uStore checks for installed components
#relevant even if the user does not select uStore as a component
#check if uStore and the Proxy Updater are installed on the same machine. this is a bit NO NO!
$uStore_Installed= @()
$uStore_Installed=$Installed_Software_NonFormatted | Where-Object {$_.DisplayName -eq 'XMPie uStore'}
$uStore_Proxy_Updater_Installed=@()
$uStore_Proxy_Updater_Installed=$Installed_Software_NonFormatted | Where-Object {$_.DisplayName -eq 'XMPie Proxy Updater Service'}
if (($uStore_Installed) -and ($uStore_Proxy_Updater_Installed)) {
	$ErrorCount++
	wtf "Both uStore and the Proxy Updater service are installed on the same machine.`r`nThis causes major issues with the functionality of uStore." "" e "The Proxy Updater should only be installed on a separate web/proxy server.`r`nIf there is no web/proxy server, then consider removing the Proxy Service and installing the full version of Helicon."
}
else {
	wtf "uStore and the Proxy Updater and not installed on the same machine" "" g
}

#check if WebDAV Publishing is installed with the Proxy Updater on the same machine. this can be problematic
$WebDAVPublishing = FeatureInstalled Web-DAV-Publishing
if (($WebDAVPublishing -eq 1) -and ($uStore_Proxy_Updater_Installed)) {
	$WarningCount++
	wtf "Both the Proxy Updater service and WebDAV Publishing are installed on the same machine, and this can cause problems.`r`n" "" w "If WebDAV Publishing is still needed, then you need to apply a workaround.`r`nSee an email from Ohad Cohen sent on October 10, 2019`r`n`r`nYou can remove the WebDAV feature by running the following command in PowerShell as an admin:`r`nUninstall-WindowsFeature Web-DAV-Publishing"
}
else {
	wtf "WebDAV Publishing and the Proxy Updater are not installed on the same machine" "" g
}

#uStore 11.1 can deal with having WebDAV installed on the same server, so we check only lower versions
if (($WebDAVPublishing -eq 1) -and ($uStore_Installed) -and ($uStoreBuild -lt 6428)) {
	$WarningCount++
	wtf "Both uStore and WebDAV Publishing are installed on the same machine, and in this version of uStore it is problematic.`r`n" "" w "You should consider upgrading uStore to 11.1 and above, or removing WebDAV Publishing if it is no longer needed.`r`nSee an email from Ohad Cohen sent on October 10, 2019`r`n`r`nYou can remove the WebDAV feature by running the following command in PowerShell as an admin:`r`nUninstall-WindowsFeature Web-DAV-Publishing"
}
else {
	wtf "uStore and WebDAV Publishing are not installed on the same machine" "" g
}

#uStore check for the availability of the licensing server. if it is not available, then uStore updates will not work
#the 404 response is also good, since it means that the server itself is reachable
if ($Components -match "[r]") {
	Write-Output "uStore: check if the XMPie licensing server can be reached"
	$XMPieLicensingServerStatus = Get-UrlStatusCode 'https://licensing.xmpie.com'
	if (($XMPieLicensingServerStatus -ne "200") -and ($XMPieLicensingServerStatus -ne "404")) {
		$WarningCount++
		wtf "uStore: XMPie licensing server cannot be reached. Reply:" "$XMPieLicensingServerStatus`r`n" w "The server at https://licensing.xmpie.com needs to be reached from the uStore server, in order to be able to install updates.`r`nEven a 404 reply (page not found) is a good reply, because it means that we reach the server and get the message from it."
	}
	else {
		wtf "uStore: XMPie licensing server can be reached" "" g
	}
}




###Marketing Console checks begin
if ($Components -match "[m]") {
	Write-Output "Marketing Console tests"
	#is MC even installed?
	$MCInstalled=$Installed_Software | findstr -i /C:"XMPie uProduce Marketing Console" | Measure-Object -Line | Select-Object -expand Lines
	if ($MCInstalled) {
		wtf "Marketing Console installation found" "" g

		#let's check the paths, and see that there are no blocked files
		#is there any MC paths value in the system registry?
		$MC_WebService_path_available = RegKey $Reg_MC_Location $Reg_MC_WebServices_path
		$MC_WebSite_path_available = RegKey $Reg_MC_Location $Reg_MC_WebSite_path
		if ((!$MC_WebService_path_available) -and (!$MC_WebSite_path_available)) {
			if ($Components -match "[z]") {
				$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nMarketing Console paths do not exist in the system registry"
			}
			else {
				$ErrorCount++
				wtf "Marketing Console paths do not exist in the system registry" "" e
			}
		}
		elseif ($MC_WebService_path_available) {
			$MCServiceBlockedFiles = ""
			$MCServiceBlockedFiles = Get-ChildItem $MC_WebService_path_available -Recurse | Where-Object -FilterScript{[System.Security.Policy.Zone]::CreateFromUrl($_.FullName).SecurityZone -eq 'Internet'}
			if ($MCServiceBlockedFiles) {
				$ErrorCount++
				wtf "There are files that are marked as blocked (downloaded from the internet)`r`nin the folder $MC_WebService_path_available" $MCServiceBlockedFiles e
			}
		}
		elseif ($MC_WebSite_path_available) {
			$MCSiteBlockedFiles = ""
			$MCSiteBlockedFiles = Get-ChildItem $MC_WebSite_path_available -Recurse | Where-Object -FilterScript{[System.Security.Policy.Zone]::CreateFromUrl($_.FullName).SecurityZone -eq 'Internet'}
			if ($MCSiteBlockedFiles) {
				$ErrorCount++
				wtf "There are files that are marked as blocked (downloaded from the internet)`r`nin the folder $MC_WebSite_path_available" $MCSiteBlockedFiles e
			}
		}

		#checking if MC is intalled, by looking in the registry. this is where the DB connection details are
		$MCInstalledRegistry = Get-ItemProperty -Path $Reg_MC_Location -ErrorAction SilentlyContinue

		#if MC is installed, is there a 'Analytics' item in the License table?
		Write-Output "Checking MC license"
		if ($MCInstalledRegistry) {
			#relevant only if we have the uProduceSQL DB details in order to check the license table
			if (($MCInstalledRegistry) -and (!$SQLLicenseMC) -and ($uProduceSQL)) {
				$ErrorCount++
				wtf "Marketing Console installed, but there is no license" "" e
			}
			else {
				wtf "Marketing Console is both installed and licensed" "" g
			}
		}

		#XMPDBTRACKING is a trustworthy database
		#if it is not set as trustworthy, then we have issues in Marketing Console when displaying certain reports
		#checking only if is a Director or extension
		#
		#the following query from Viktor Schimanovich looks for version and build number, so it can be used as an indication that MC is installed somewhere:
		#SELECT CONVERT(varchar(10), [versionNumber]) + '.' + CONVERT(varchar(10), [buildNumber] ) AS Version FROM [XMPDBTRACKING].[XMPieTracking].[VersionInfo]
		#
		#for now, we will not check if there is a DB entry. sometimes in migrations the client decides to stop using MC, and the entry is still there
		# $MCLargeVersionValue = SQLValue $SQLDefault XMPDBTRACKING "$DB_User" "$DB_Password" -sqlText "SELECT [versionNumber] FROM [XMPDBTRACKING].[XMPieTracking].[VersionInfo]"
		# if (($MCInstalledRegistry) -or ($MCLargeVersionValue)) {
		Write-Output "Checking XMPDBTRACKING trustworthy"
		$TrackingDBTrustworthyQuery = "SELECT is_trustworthy_on FROM master.sys.databases where name='XMPDBTRACKING'"
		$TrackingDBTrustworthyValue = SQLValue  $SQLDefault master "$CompatUser" "$CompatPass" -sqlText "$TrackingDBTrustworthyQuery"
		#in case the DB does not exist, then we get an empty value, so the best test is to check against values that we know: true or false
		if ($TrackingDBTrustworthyValue -eq $False) {
			$WarningCount++
			wtf "The database XMPDBTRACKING should be set as trustworthy, and it is not`r`n" "" w "When the XMPDBTRACKING database is not set as trustworthy, Marketing Console reports can have errors in them.`r`n`r`nYou can solve this by running the following query:`r`nALTER DATABASE XMPDBTRACKING SET TRUSTWORTHY ON`r`n`r`nIf you want to check that the value is correct, then it should be 1 when running the following query:`r`n$TrackingDBTrustworthyQuery`r`n`r`nYou can also see it in SQL Studio (SSMS), by going to the database Properties > Options and then looking for the word Trustworthy:`r`nhttps://i.imgur.com/9LoXovF.png"
		}
		elseif ($TrackingDBTrustworthyValue -eq $True) {
			wtf "The database XMPDBTRACKING is set as trustworthy" "" g
		}
		else {
			wtf "The database XMPDBTRACKING could not be tested to see if it is trustworthy. No valid value returned" "" g
		}
	}
	else {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`Marketing Console is not in the Windows programs list"
		}
		else {
			$ErrorCount++
			wtf "Are you sure that Marketing Console is installed? It is not in the Windows programs list" "" e
		}
	}
}
###Marketing Console checks end


#Adobe InDesign Server installation checks
#the amount of times we have InDesign in the list of installed software
if ($Components -match "[i]") {
	Write-Output "Checking the amount of times we have InDesign in the list of installed software"
	$InDesign_number=$Installed_Software | findstr -i "InDesign" | Measure-Object -Line | Select-Object -expand Lines
	$InDesign_numberNonWow=$Installed_SoftwareNonWow | findstr -i "InDesign" | Measure-Object -Line | Select-Object -expand Lines
	$InDesign_installs=$Installed_Software | findstr -i "InDesign"
	$InDesign_installsNonWow=$Installed_SoftwareNonWow | findstr -i "InDesign"
	if (($InDesign_number -eq 0) -and ($InDesign_numberNonWow -eq 0)) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nInDesign Server is not in the Windows programs list"
		}
		else {
			$ErrorCount++
			wtf "Are you sure that InDesign Server is installed? It is not in the Windows programs list" "" e
		}
	}
	elseif (($InDesign_number -eq 1) -or ($InDesign_numberNonWow -eq 1)){
		wtf "InDesign Server is installed only once:" "$InDesign_installs $InDesign_installsNonWow" g
	}
	else {
		$NoticeCount++
		wtf "InDesign Server is installed multiple times: $InDesign_number $InDesign_numberNonWow" "$InDesign_installs`r`n$InDesign_installsNonWow" n "XMPie plugin files will be installed in the folder of the highest version"
	}
}


#uImage related checks
if ($Components -match "[g]") {
	Write-Output "Performing uImage and Photoshop checks"
	$PhotoshopPluginWarning = "This can cause the uImage plugin to not be installed.`r`nIt is advised to open Photoshop, and then to look in 'File > Automate' for the uImage entries.`r`nCommon solution would be to re-install or update Photoshop.`r`n`r`nFor additional troubleshooting, contact XMPie Support. For XMPie Support: consult the following internal Knowledge Base Article:`r`nAdobe Photoshop not processing uImage calls"
	#is Photoshop installed, and if so then how many times?
	$Photoshop_number=$Installed_Software | findstr -i "Photoshop" | Measure-Object -Line | Select-Object -expand Lines
	$Photoshop_numberNonWow=$Installed_SoftwareNonWow | findstr -i "Photoshop" | Measure-Object -Line | Select-Object -expand Lines
	$Photoshop_installs=$Installed_Software | findstr -i "Photoshop"
	$Photoshop_installsNonWow=($Installed_SoftwareNonWow | findstr -i "Photoshop" | Format-Table | out-string).Trim()
	if (($Photoshop_number -eq 0) -and ($Photoshop_numberNonWow -eq 0)) {
		if ($Components -match "[z]") {
			$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nPhotoshop is not in the Windows programs list"
		}
		else {
			#no phothoshop is installed, but it is expected
			$ErrorCount++
			wtf "Are you sure that Photoshop is installed? It is not in the Windows programs list" "" e
		}
	}
	else {
		#we do have Photoshop installed. let's start the checks
		Write-Output "uImage: searching registry for relevant keys"
		$Reg_Photoshop_MainLocation="HKLM:\SOFTWARE\Classes\Photoshop.Application\CLSID"
		$Reg_Photoshop_MainLocationKey = '(Default)'
		#for some reason, the RegKey function would not return a value for this one, so we are using the exact syntax of the function literaly
		$PhotoshopCLSID = (Get-ItemProperty -Path $Reg_Photoshop_MainLocation -Name $Reg_Photoshop_MainLocationKey -ErrorAction SilentlyContinue).$Reg_Photoshop_MainLocationKey
		if ($PhotoshopCLSID) {
			wtf "Photoshop registry record found in $Reg_Photoshop_MainLocation" "" g
			$Reg_Photoshop_Main_CLSID ="Registry::HKEY_CLASSES_ROOT\CLSID\$PhotoshopCLSID"
			# $PhotoshopCLSIDFound = Search-Registry -Path "$Reg_Photoshop_Main_CLSID" -Recurse -ValueNameRegex "$PhotoshopCLSID" -ErrorAction SilentlyContinue | Format-List
			$PhotoshopCLSIDFound = (Get-ItemProperty -Path $Reg_Photoshop_Main_CLSID -ErrorAction SilentlyContinue)
			if ($PhotoshopCLSIDFound) {
				wtf "Photoshop CLSID value $PhotoshopCLSID found in:" "$Reg_Photoshop_Main_CLSID" g
			}
			else {
				$WarningCount++
				wtf "Photoshop CLSID value $PhotoshopCLSID was not found in:" "$Reg_Photoshop_Main_CLSID" w "$PhotoshopPluginWarning"
			}
		}
		else {
			$ErrorCount++
			wtf "Photoshop registry value not found in expected location:" "$Reg_Photoshop_MainLocation" e "$PhotoshopPluginWarning"
		}

		#checking amount of installed Photoshop
		Write-Output "uImage: checking if Photoshop is installed"
		if (($Photoshop_number -eq 1) -or ($Photoshop_numberNonWow -eq 1)){
			wtf "Photoshop is installed only once:" "$Photoshop_installs $Photoshop_installsNonWow" g
		}
		else {
			$WarningCount++
			wtf "Photoshop is installed multiple times: $Photoshop_number $Photoshop_numberNonWow" "$Photoshop_installs`r`n$Photoshop_installsNonWow" w "uImage plugin files will be installed in the folder of the highest version"
		}
	}

	#there is a specific value (0) that needs to be set in the registry for the relevant service to run
	#irrelevant for PE 9.3.1 and above. uProduce build: 11070
	if ($uProduceBuild -and $uProduceBuild -lt 11070) {
		Write-Output "uImage: uProduce build lower than 11070 (9.3.1), so looking for Non-Interactive Services"
		$InteractiveServicesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Windows"
		$InteractiveServicesRegValue = RegKey $InteractiveServicesRegPath "NoInteractiveServices"
		if ($InteractiveServicesRegValue -ne 0) {
			$ErrorCount++
			wtf "Non-Interactive services are not set up correctly in the system registry with the value 0`r`n" "" e "This is the location that should have 0 in it:`r`nHKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows\NoInteractiveServices"
		}
		else {
			wtf "Non-Interactive services are set up correctly in the system registry with the value 0" "" g
		}

		#the service does not need to run in any case, but if it does not then the user should know about it
		$Services_stopped_Interactive = (Get-Service UI0Detect | Where-Object {$_.Status -eq "Stopped"} | Select-Object Status,Name,DisplayName | Format-List | out-string).Trim()
		if ($Services_stopped_Interactive) {
			$WarningCount++
			wtf "The Interactive Services Detection service is stopped. For your consideration:" $Services_stopped_Interactive w
		}
		else {
			wtf "The Interactive Services Detection service is up and running" "" g
		}
	}
	
	#PE 9.3.1 and above run the PlanParts service as a hidden service, and it if stops it is very hard to know it
	if ($uProduceBuild -and $uProduceBuild -ge 11070) {
		Write-Output "uImage: uProduce version is 11070 (9.3.1) or higher, so checking PlanParts as a hidden service"
		#checking if there is a "hidden" uImage PlanParts process running
		$XMPPlanPartsAmount = Get-WmiObject Win32_Process -Filter "CommandLine LIKE '%XMPServicePLANPARTS%'"
		#if we do not have a process, then we start with the errors
		if (!$XMPPlanPartsAmount) {
			#there are 2 possible cases: there is nothing wrong with the location of the general service executable, or there is
			#first: if there is nothing wrong
			if (!$XMPPlanServiceExecIssues) {
				$XMPPlanPartsServiceFullPath = "$($XMPiePath)$($XMPServiceExecFile.Name)"
				$XMPPlanPartsRunCommand = "start-process -filepath $XMPPlanPartsServiceFullPath XMPServicePLANPARTS"
				if ($Components -match "[z]") {
					$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nuImage PlanParts service not found, so uImage will not work. You can start the service by running the following command in PowerShell:`r`n$XMPPlanPartsRunCommand"
				}
				else {
					$ErrorCount++
					wtf "uImage: the PlanParts service is not running, so uImage will not work." "" e "You can start the service by running the following command in PowerShell:`r`n$XMPPlanPartsRunCommand"
				}
			}
			#second: if there is indeed something wrong with the service executable
			else {
				$XMPPlanPartsServiceFullPathIssue = "$($XMPiePath)\XMPService_v###_x64_R.exe"
				$XMPPlanPartsRunCommandIssue = "start-process -filepath $XMPPlanPartsServiceFullPathIssue XMPServicePLANPARTS"
				if ($Components -match "[z]") {
					$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nuImage PlanParts service not found, so uImage will not work.`r`nHowever, there were issues found with the XMPie service executable file. Look in the log file for more details.`r`nOnce you deal with the issues, you will be able to start the service by running the following command in PowerShell:`r`n$XMPPlanPartsRunCommandIssue"
				}
				else {
					$ErrorCount++
					wtf "uImage: the PlanParts service is not running, so uImage will not work.`r`nHowever, there were issues found with the XMPie service executable file. Look in the log file for more details." "" e "Once you deal with the issues, you will be able to start the service by running the following command in PowerShell:`r`n$XMPPlanPartsRunCommandIssue"
				}
			}
		}
	}

}


# searching the registry for services marked for deletion
Write-Output "Searching the registry for services marked for deletion"
$ServicesForDeletion=Search-Registry -Path HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -ValueNameRegex "DeleteFlag" -ErrorAction SilentlyContinue | Format-List
if ($ServicesForDeletion) {
	$WarningCount++
	wtf "There might be services that are marked for deletion!`r`n" "" w "Look for the key DeleteFlag in the following locations:`r`n$ServicesForDeletion"
}
else {
	wtf "No services are marked for deletion" "" g
}


#checking if Windows Defender RealTime protection is off as recommended
Write-Output "Checking if Windows Defender Real-Time protection is off"
$WinDefenderStatus = Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled
$WinDefenderStatusList = ($WinDefenderStatus  | Format-List | out-string).Trim()
$WinDefenderCloudStatus = Get-MpPreference | Select-Object -Property MAPSReporting,SubmitSamplesConsent
$WinDefenderCloudStatusList = ($WinDefenderCloudStatus | Format-List | out-string).Trim()
if (($WinDefenderStatus.RealTimeProtectionEnabled) -or ($WinDefenderStatus.BehaviorMonitorEnabled) -or ($WinDefenderStatus.IoavProtectionEnabled) -or ($WinDefenderStatus.NISEnabled) -or ($WinDefenderStatus.OnAccessProtectionEnabled) -or ($WinDefenderCloudStatus.MAPSReporting) -or ($WinDefenderCloudStatus.SubmitSamplesConsent)) {
	$NoticeCount++
	wtf "Windows Defender protection (or one of its options) is on:" "$WinDefenderStatusList`r`n$WinDefenderCloudStatusList`r`n" n "From the PE installation guide:`r`nIn order to maintain good performance, it is recommended that you turn off Windows Defender in Windows Server.`r`n`r`nTo disable Windows Defender on Windows Server:`r`n1. Start Windows and open the Server Manager`r`n2. Open the Local Server>Properties screen`r`n3. Next to Windows Defender, click the Real-Time Protection: On link`r`n4. In the Settings dialog box, turn off Windows Defender options"
}
else {
	wtf "Windows Defender protection and its options are off, as recommended" "" g
}


#Windows updates installed in the last X days
#from here:
# https://blogs.technet.microsoft.com/heyscriptingguy/2017/02/03/powertip-get-a-list-of-security-patches-installed-in-the-last-90-days/
if ($Days) {
	$WindowsUpdates_Days=$Days
}
else {
	$WindowsUpdates_Days=14
}
Write-Output "Checking for installed Windows updates in the last $WindowsUpdates_Days days"
$WindowsUpdates_Installed = (Get-WmiObject -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime()}} | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-$WindowsUpdates_Days) } | out-string).Trim()
# Write-Output var: $WindowsUpdates_Installed
if ($WindowsUpdates_Installed) {
	$WarningCount++
	wtf "Windows updates were installed in the last $WindowsUpdates_Days days" $WindowsUpdates_Installed w
	#if there are updates, then we write them to the info section, for future reference
	wtf "Installed Windows updates in the last $WindowsUpdates_Days days:" $WindowsUpdates_Installed i
}
else {
	#hold on! if too much time passed without an update, then this is also worth mentioning
	#how about 60 days?
	if ($Days) {
		$WindowsUpdates_DaysNotInstalled=$Days
	}
	else {
		$WindowsUpdates_DaysNotInstalled=60
	}
	Write-Output "Checking if Windows updates were not installed in the last $WindowsUpdates_DaysNotInstalled days"
	$WindowsUpdates_NotInstalled=Get-WmiObject -Class "win32_quickfixengineering" | Select-Object -Property "Description", "HotfixID", @{Name="InstalledOn"; Expression={([DateTime]($_.InstalledOn)).ToLocalTime()}} | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-$WindowsUpdates_DaysNotInstalled) }
	if ($WindowsUpdates_NotInstalled) {
		wtf "Windows updates installed in the last $WindowsUpdates_DaysNotInstalled days, but not in the last $WindowsUpdates_Days days" "" g
	}
	else {
		$WarningCount++
		wtf "No Windows updates installed in the last $WindowsUpdates_DaysNotInstalled days" $WindowsUpdates_NotInstalled w
	}
}


#checking if there are any failed or errored Windows updates
#source:
#https://www.thewindowsclub.com/check-windows-update-history-using-powershell
# Convert Wua History ResultCode to a Name # 0, and 5 are not used for history # See https://msdn.microsoft.com/en-us/library/windows/desktop/aa387095(v=vs.85).aspx
Write-Output "Checking for failed or partial Windows updates"
function Convert-WindowsUpdateResultCodeToName
{
	param(
		[Parameter(Mandatory=$true)]
		[int] $ResultCode
	)
	$Result = $ResultCode
	switch($ResultCode)
	{
		2 {$Result = "Succeeded"}
		3 {$Result = "Succeeded With Errors"}
		4 {$Result = "Failed"}
	}
	return $Result
}

function Get-WindowsUpdateHistory
{
	# Get a WUA Session
	$session = (New-Object -ComObject 'Microsoft.Update.Session')
	# Query the latest 1000 History starting with the first recordp
	$history = $session.QueryHistory("",0,50) | ForEach-Object {
		if (($_.ResultCode -eq 3) -or ($_.ResultCode -eq 4)) {
			$Result = Convert-WindowsUpdateResultCodeToName -ResultCode $_.ResultCode
			# Make the properties hidden in com properties visible.
			$_ | Add-Member -MemberType NoteProperty -Value $Result -Name Result
			$Product = $_.Categories | Where-Object {$_.Type -eq 'Product'} | Select-Object -First 1 -ExpandProperty Name
			$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.UpdateId -Name UpdateId
			$_ | Add-Member -MemberType NoteProperty -Value $_.UpdateIdentity.RevisionNumber -Name RevisionNumber
			$_ | Add-Member -MemberType NoteProperty -Value $Product -Name Product -PassThru
			#commenting the following line, as it is relevant for display but we only log the output
			# Write-Output $_
		}
	}
	#Remove null records and only return the fields we want
	#there are updates that we shuold ignore their failure. add more '-or' conditions when needed
	#KB2267602 - Windows Defender definitions. Fails when another Antivirus exists. We do not care about this update
	#as a matter of fact, we should not care about anything that has to do with Windows Defender or Antivirus updates. Ignoring all of them.
	#MS Office seems to be a rising star with a lot of failed updates that we do not really care about, so ignoring
	$history |
	Where-Object {(!$_.title.contains('KB2267602') -and !$_.title.contains('Antivirus') -and !$_.product.contains('Office') -and !$_.product.contains('Defender')  -and !$_.title.contains('Defender') -and !$_.title.contains('Flash') -and !$_.title.contains('Explorer') -and !$_.title.contains('Malicious') -and !$_.title.contains('Adobe Flash')) -and ![String]::IsNullOrWhiteSpace($_.title)} |
	Select-Object Result, Date, Title, SupportUrl, Product, UpdateId, RevisionNumber
}

$WindowsUpdateStatus = (Get-WindowsUpdateHistory | Format-Table | out-string).Trim()
if ($WindowsUpdateStatus) {
	$NoticeCount++
	wtf "There are Windows updates that either failed or succeeded with errors:" "$WindowsUpdateStatus" n
}
else {
	wtf "Windows update: no failed updates found " "" g
}



#are there any *xmp* scheduled tasks that have a non-successful result
#we are ignoring cases of:
# empty last run details, since new installations do not have a last run
# 267009 - Task is currently running
# 267011 - Task has not yet run
# 2147750687 - An instance of this task is already running
#status numbers taken from the following link, after not finding another resource:
#http://systemcenter.no/?p=1142
#there is a special exception for the uImage Photoshop Dialog Sentinel that is getting a permanent notice:
#The operator or administrator has refused the request (Error 0x800710E0)
Write-Output "Checking if there are any scheduled tasks that did not run successfully"
$SchedTaskFail = (schtasks /query /v /fo csv | ConvertFrom-CSV | Select-Object -Property "TaskName","Last Result" | Where-Object {($_.TaskName -like "*xmp*") -and ($_."Last Result" -notlike "0") -and ($_."Last Result" -notlike "1") -and ($_."Last Result" -notlike "") -and ($_."Last Result" -notlike "267009") -and ($_."Last Result" -notlike "267011") -and ($_."Last Result" -notlike "2147750687") -and (($_."Last Result" -notlike "2147020576") -and ($_."TaskName" -notlike "\XMPieDialogSentinel"))} | Format-Table | out-string).Trim()
if ($SchedTaskFail) {
	$ErrorCount++
	wtf "There are XMP scheduled tasks that failed to run" $SchedTaskFail e
}
else {
	wtf "All XMP scheduled tasks had a successful last run" "" g
}



###begin extensions checks
#only checking for 'extensions' features if there are any known features there AND it is not a director
#I could have just used the 't' indication for an extension, but what if the user doesn't notice it? the chosen test covers both options
if (($Components -match "[txieg]") -and ($Components -notmatch "[ad]")) {
	Write-Output "Extensions tests"
	#and now, to the million Drachmas question: where, in the extension, can we get the name/IP of the director?
	#
	#one of the places may be:
	#C:\XMPie\XMPieExec\XMPieMonitorTaskScheduler.exe.config
	#in the first line that contains:
	#<endpoint address="http://DIRECTOR/XMPieMonitorToolsAPIWCF/MonitorToolAPIWCF.svc" binding="basicHttpBinding"
	#
	#eventually, right now the most reliable place is in the DB, so:
	if ($uProduceSQL) {
		$DirectorMSMQAddressSQL = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [pathValue] FROM [XMPDB2].[XMPie].[TBL_PATH_LOCATOR] where pathName = 'MSMQServerName'"
		if ($DirectorMSMQAddressSQL) {
			#Message Queue connection test to the director
			#TODO: when there is no domain user, we get a permissions error, so for now this test is commented out
			if (1 -eq 2) {
				$MSMQConnectTest = Get-WmiObject -class Win32_PerfRawData_MSMQ_MSMQQueue -computerName $DirectorMSMQAddressSQL | Format-Table -prop Name, MessagesInQueue
				if ($MSMQConnectTest) {
					wtf "Message queue in director $DirectorMSMQAddressSQL can be reached" "" g
				}
				else {
					$ErrorCount++
					wtf "Message queue in director $DirectorMSMQAddressSQL cannot be reached" "" e
				}
			}
			#port 80 connection test to the director
			$Ports80Director = New-Object Net.Sockets.TcpClient
			$Ports80Director.Connect($DirectorMSMQAddressSQL,80)
			if($Ports80Director.Connected) {
				wtf "Director $DirectorMSMQAddressSQL can be reached on port 80" "" g
			}
			else {
				$ErrorCount++
				wtf "Director $DirectorMSMQAddressSQL cannot be reached on port 80" "" e
			}
		}
	}
}

#director and extensions / uImage UPU connectivity tests
#TODO: decide if we need to check this, since the extensions anyway try to get to the Director's queue
#and in Active-Active configurations we have the NLB address so there is no way for us to know if we are on a real Director
if (($Components -match "[adtg]") -and (1 -eq 2)) {
	#if it is a director, then we search for all the other owners
	#if it is an extension / UPU, then we need to search for the director
	#and if the user chose to run all tests? darn. I will need to make it a bit more sophisticated than I wanted it to be
	#at the end, it all comes down to the License table
	#and it is only relevant if we have a Director component. otherwise, there is no use checking for any extensions
	$DirectorInLicense = SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [Type] FROM [XMPDB2].[XMPie].[TBL_LICENSE] where Type='DIRECTOR_COMP'"
	if ($DirectorInLicense -ne "") {
		#get an array with separate name and IP
		# $DirectorLicenseOwner = SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [Owner] FROM [XMPDB2].[XMPie].[TBL_LICENSE] where Type='DIRECTOR_COMP'"
		# this is the one that we used:
		# $DirectorLicenseOwner = SQLValue $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [Owner] FROM [XMPDB2].[XMPie].[TBL_LICENSE] where Type='DIRECTOR_COMP'"
		# $SplitLicenseOwnerName = @($DirectorLicenseOwner -split '[ ()]'| Where { $_ -and $_.Trim() })[0]
		# $SplitLicenseOwnerIP = @($DirectorLicenseOwner -split '[ ()]'| Where { $_ -and $_.Trim() })[1]
		$SQLLicenseFull = SQLProcess $uProduceSQL xmpdb2 "$DB_User" "$DB_Password" -sqlText "SELECT [CDKey],[Type],[Active],[Owner],[ActivationDate] FROM [XMPDB2].[XMPie].[TBL_LICENSE]"
		# $TestPosrtAccessibility = Test-NetConnection -ComputerName LOCALHOST -Port 80 -InformationLevel Quiet
	}
}


###end extensions checks



#IIS Prerequisites - roles and features
if ($Components -match "[rdaf]") {
	Write-Output "Checking for IIS Prerequisites"
	$Features_IIS = @('Web-Server','Web-Custom-Logging','Web-Log-Libraries','Web-Basic-Auth','Web-Cert-Auth','Web-Windows-Auth','Web-Cert-Auth','Web-Net-Ext45','Web-ASP','Web-Asp-Net','Web-Asp-Net45','Web-Mgmt-Tools','Web-Mgmt-Compat','Web-Lgcy-Mgmt-Console','Web-Lgcy-Scripting','Web-Scripting-Tools','Web-Mgmt-Service','NET-WCF-HTTP-Activation45')
	#historically, the following was in the list, but not in any installation guide that I could find
	#I reluctantly kept it, since there was no person that could tell me if it is really needed.
	#it was eventually removed, on 2020-08-18 (thanks to Viktor Schimanovich paying attention)
	#Web-Http-Redirect
	#
	#The following features were a part of the StoreFlow installer, but they are not found in the installation guide so I removed them
	#They might be needed for FFC, but the FFC installer takes care of its own features anyway
	#,'Web-Request-Monitor','Web-Http-Tracing','NET-WCF-MSMQ-Activation45'
	$Features_IIS_NotFound = @()
	$FeatureCheck_IIS_NoCheck = "0"
	foreach ($Feature in $Features_IIS) {
		$FeatureCheck_IIS = FeatureInstalled $Feature
		if ($FeatureCheck_IIS -eq "NA") {
			$FeatureCheck_IIS_NoCheck = "1"
			break
		}
		if ($FeatureCheck_IIS -eq 0 -and $FeatureCheck_IIS -ne "NA") {
			$Features_IIS_NotFound += $Feature
		}
	}
	
	if ($FeatureCheck_IIS_NoCheck -ne 1) {
		if ($Features_IIS_NotFound){
			$WarningCount++
			$Features_IIS_NotFound_Joined = $Features_IIS_NotFound -join ","
			wtf "There are IIS features that are not installed." "$Features_IIS_NotFound" w "You can install these features using PowerShell as an admin using the following command:`r`nInstall-WindowsFeature $Features_IIS_NotFound_Joined"
		}
		else {
			wtf "All IIS features are installed" "" g
		}
	}
	else {
		wtf "Cannot test IIS features because the PowerShell Cmdlet Get-WindowsFeature does not exist. This is common in desktop systems" "" g
	}
}


#.NET framework Prerequisites
if ($Components -match "[rdaf]") {
	Write-Output "Checking for .NET framework Prerequisites"
	$FeatureCheck_DotNet=FeatureInstalled NET-Framework-Core
	if ($FeatureCheck_DotNet -eq 0 -and $FeatureCheck_DotNet -ne "NA"){
		$WarningCount++
		wtf "The .Net feature is not installed.`r`nFeature name:`r`nNET-Framework-Core" ""w
	}
	else {
		if ($FeatureCheck_DotNet -ne "NA") {
			wtf "The .Net feature is installed" "" g
		}
		else {
			wtf "Cannot test .Net feature isntallation because the PowerShell Cmdlet Get-WindowsFeature does not exist. This is common in desktop systems" "" g
		}
	}
}


#MSMQ
if ($Components -match "[daf]") {
	Write-Output "Checking for MSMQ"
	$Features_MSMQ = @('MSMQ')
	#The following features were a part of the StoreFlow installer, but they are not found in the installation guide so I removed them
	#They might be needed for FFC, but the FFC installer takes care of that anyway
	#,'MSMQ-Directory','MSMQ-HTTP-Support'
	#in addition, the uStore installation guide does not specify MSMQ, so I removed it from the components list
	$FeatureCheck_MSMQ_NoCheck = "0"
	$Features_MSMQ_NotFound = @()
	foreach ($Feature in $Features_MSMQ) {
	   $FeatureCheck_MSMQ=FeatureInstalled $Feature
		if ($FeatureCheck_MSMQ -eq "NA") {
			$FeatureCheck_MSMQ_NoCheck = "1"
			break
		}
	   if ($FeatureCheck_MSMQ -eq 0 -and $FeatureCheck_MSMQ -ne "NA") {
		$Features_MSMQ_NotFound += $Feature
	   }
	}
	
	if ($Features_MSMQ_NotFound){
		$WarningCount++
		$Features_MSMQ_NotFound_Joined = $Features_MSMQ_NotFound -join ","
		wtf "There are MSMQ features that are not installed." "$Features_MSMQ_NotFound" w "You can install these features using PowerShell as an admin using the following command:`r`nInstall-WindowsFeature $Features_MSMQ_NotFound_Joined"
	}
	elseif ($FeatureCheck_MSMQ_NoCheck -ne 1) {
		wtf "All MSMQ features are installed" "" g
		Write-Output "Checking if MSMQ is stopped"
		$Services_stopped_MSMQ=(Get-Service msmq | Where-Object {$_.Status -eq "Stopped"} | Select-Object Status,Name,DisplayName | Format-Table | out-string).Trim()
		if ($Services_stopped_MSMQ) {
			$ErrorCount++
			wtf "The MSMQ service is stopped:" "$Services_stopped_MSMQ" e "Many of the XMPie services rely on this service to run. It is not optional"
		}
		else {
			wtf "The MSMQ service is up and running" "" g
		}
	}
	else {
		wtf "Cannot test MSMQ features isntallation because the PowerShell Cmdlet Get-WindowsFeature does not exist. This is common in desktop systems" "" g
	}

}


###begin FFC checks
#TODO: check if FFC is even installed
#TODO: once we decide if and what we want to check in FFC - implement it
if ($Components -match "[f]") {
	Write-Output "Looking into FreeFlow Core"
	#First, let's check if FFC is even installed
	# $FFCInstalled = $Installed_Software | grep "FreeFlow"
	$FFCInstalled = $Installed_Software | findstr -i "FreeFlow"
	$FFCInstalledNonWow = $Installed_SoftwareNonWow | findstr -i "FreeFlow"
		if (($FFCInstalled) -or ($FFCInstalledNonWow)){
			#check if there is an FFC installation location in the registry
			$FFC_Path=RegKey $Reg_FFC_Location $Reg_FFC_InstallDir
			if ($FFC_Path) {
				#wtf "FFC path is:" "$FFC_Path" d
				#there are some details in the config file, so let's load them
				# $FFC_ConfigFile_Location=$FFC_Path + "\Platform\Config\Configuration.xml"
				$FFC_Fixed_ConfigFile_Location='C:\Program Files\Xerox\FreeFlow Core\Platform\Config\Configuration.xml'
				#apparently, not in all FFC installations we find the file in the expected location
				#since we still do nothing with this section, it is best to keep it under an 'if'
				if (Test-Path -Path $FFC_Fixed_ConfigFile_Location) {
					[XML]$FFC_ConfigFile_Contents=Get-Content "$FFC_Fixed_ConfigFile_Location"
					$FFC_DB_Hostname=($FFC_ConfigFile_Contents.Credentials).hostname
					$FFC_DB_Instance=($FFC_ConfigFile_Contents.Credentials).instanceId
					$FFC_DB_ServerAndInstance=$FFC_DB_Hostname + "\" + $FFC_DB_Instance
					#unsure what this is. The value is .\xmpie
					# $FFC_DataSource=($FFC_ConfigFile_Contents.Credentials).datasource
					# $FFC_DB_Master="OapMasterDatabase"
					# $FFC_DB_Platform="OapPlatformDatabase"
					#Host Instance DBName User Password
					# $FFC_DB_Connection_String_Master=$FFC_DB_ServerAndInstance + $FFC_DB_Master
					# $FFC_DB_Connection_String_Platform=$FFC_DB_ServerAndInstance + $FFC_DB_Platform
				}
				#Now, the only thing left to do is to actually do something with all of this information
				#or in other words:
				#TODO: everything
			}
			else {
			#all this is commented, since there were changes in FFC 5.1.1.0 that change this behavior.
			#we cannot keep on checking until we update the needed validation
				#Write-Output "Could not find a FFC path in the registry"
				#$ErrorCount++
				#wtf "FreeFlow Core installed, but there is no FFC path in the system registry" "" e
			}
		}
		else {
			if ($Components -match "[z]") {
				$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nFreeFlow Core is not in the Windows programs list"
			}
			else {
				$ErrorCount++
				wtf "Are you sure that FreeFlow Core is installed? It is not in the Windows programs list" "" e
			}
		}
}

###end FFC checks



###uStore tests with long (and tedious) output, so we put them at the end of the log file
#uStore checks for problematic orders
if ($Components -match "[r]") {
	if ($uStoreSQL) {
		Write-Output "uStore: check for problematic order products with NULL handling status"
		$uStoreStatusChangeWarning = "IMPORTANT BEFORE YOU MOVE FORWARD!`r`n`r`nRunning the following query will bring old orders back to the Orders screen.`r`nOnce you change the order status, orders will appear in the Orders screen, and there needs to be a decision regarding what to do with them.`r`nFor example, there may be VERY OLD orders that should be ARCHIVED or CANCELLED right after the status change.`r`n`r`nDO NOT run the following query before you read the above warning and consult with the client!"
		$uStoreOPNULL = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT TOP (20) OP.OrderProductID FROM [uStore].[dbo].[OrderProduct] OP INNER JOIN [uStore].[dbo].[Orders] O ON O.OrderID = OP.OrderID WHERE OP.StatusID<>2 AND OP.IsDraft=0 AND O.IsCart=0 AND O.IsSaveForLater=0 AND OP.OrderHandlingStatusID IS NULL" | Format-Table | out-string).Trim()
		if ($uStoreOPNULL) {
			$WarningCount++
			#creating a query to update order product items according to known statuses
			$uStoreOPNULLListID = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -format "values" -sqlText "SELECT OP.OrderProductID FROM [uStore].[dbo].[OrderProduct] OP INNER JOIN [uStore].[dbo].[Orders] O ON O.OrderID = OP.OrderID INNER JOIN [uStore].[dbo].[Doc] DO ON DO.ProductID = OP.ProductID INNER JOIN [uStore].[dbo].[DocType] DT ON DT.DocTypeID = DO.DocTypeID WHERE OP.StatusID<>2 AND OP.IsDraft=0 AND O.IsCart=0 AND O.IsSaveForLater=0 AND OP.OrderHandlingStatusID IS NULL" | Format-Table | out-string).Trim()
			$uStoreOPNULLListID = $($uStoreOPNULLListID -split "`r`n").Trim()
			$uStoreOPNULLListType = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -format "values" -sqlText "SELECT DT.DocTypeID FROM [uStore].[dbo].[OrderProduct] OP INNER JOIN [uStore].[dbo].[Orders] O ON O.OrderID = OP.OrderID INNER JOIN [uStore].[dbo].[Doc] DO ON DO.ProductID = OP.ProductID INNER JOIN [uStore].[dbo].[DocType] DT ON DT.DocTypeID = DO.DocTypeID WHERE OP.StatusID<>2 AND OP.IsDraft=0 AND O.IsCart=0 AND O.IsSaveForLater=0 AND OP.OrderHandlingStatusID IS NULL" | Format-Table | out-string).Trim()
			$uStoreOPNULLListType = $($uStoreOPNULLListType -split "`r`n").Trim()
			# $uStoreOPNULLListType = $uStoreOPNULLListType.split("{`r`n}")
			$uStoreOPNULLUpdateQuery = ""
			$uStoreOPNULLListIndex = 0
			foreach ($uStoreOPNULLListItem in $uStoreOPNULLListID) {
				$uStoreOPNULLListTypeNOW = $uStoreOPNULLListType[$uStoreOPNULLListIndex]
				if ($uStoreOPNULLListItem -and $uStoreOPNULLListTypeNOW) {
						#kitting products (ID 14) are also treated like print products, since they require Shipping, and Email and XM products do not have that
						#this means that Kitting products will always go to the standard Pending Prints queue
						if (($uStoreOPNULLListTypeNOW -eq "1") -or ($uStoreOPNULLListTypeNOW -eq "2") -or ($uStoreOPNULLListTypeNOW -eq "4") -or ($uStoreOPNULLListTypeNOW -eq "5" -or ($uStoreOPNULLListTypeNOW -eq "14"))) {
							$uStoreOPNULLUpdateQuery = "$uStoreOPNULLUpdateQuery`r`nUPDATE [uStore].[dbo].[OrderProduct] SET OrderHandlingStatusID = 1 WHERE OrderProductID = $uStoreOPNULLListItem;"
						}
						elseif ($uStoreOPNULLListTypeNOW -eq "3") {
							$uStoreOPNULLUpdateQuery = "$uStoreOPNULLUpdateQuery`r`nUPDATE [uStore].[dbo].[OrderProduct] SET OrderHandlingStatusID = 200 WHERE OrderProductID = $uStoreOPNULLListItem;"
						}
						elseif ($uStoreOPNULLListTypeNOW -eq "8") {
							$uStoreOPNULLUpdateQuery = "$uStoreOPNULLUpdateQuery`r`nUPDATE [uStore].[dbo].[OrderProduct] SET OrderHandlingStatusID = 400 WHERE OrderProductID = $uStoreOPNULLListItem;"
						}
					}
				$uStoreOPNULLListIndex++
			}
			# $uStoreOPNULCount = SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT COUNT (*) FROM [uStore].[dbo].[OrderProduct] OP INNER JOIN [uStore].[dbo].[Orders] O ON O.OrderID = OP.OrderID WHERE OP.StatusID<>2 AND OP.IsDraft=0 AND O.IsCart=0 AND O.IsSaveForLater=0 AND OP.OrderHandlingStatusID IS NULL"
			$uStoreOPNULCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT COUNT (*) FROM [uStore].[dbo].[OrderProduct] OP INNER JOIN [uStore].[dbo].[Orders] O ON O.OrderID = OP.OrderID WHERE OP.StatusID<>2 AND OP.IsDraft=0 AND O.IsCart=0 AND O.IsSaveForLater=0 AND OP.OrderHandlingStatusID IS NULL"
			#$uStoreOPNULLText = $uStoreOPNULL | Out-String
			$uStoreOPNULLFind = "SELECT OP.OrderProductID AS `"OrderProduct`", O.EncryptedOrderId AS `"Order`", DT.DocTypeID AS `"ProductTypeID`", OP.DateAdded, DT.Name AS `"ProductType`", O.StoreID, SC.Name AS `"Store`" , PC.Name AS `"Prodct Name`"`r`nFROM [uStore].[dbo].[OrderProduct] OP`r`nINNER JOIN [uStore].[dbo].[Orders] O ON O.OrderID = OP.OrderID`r`nINNER JOIN [uStore].[dbo].[Doc] DO ON DO.ProductID = OP.ProductID`r`nINNER JOIN [uStore].[dbo].[DocType] DT ON DT.DocTypeID = DO.DocTypeID`r`nINNER JOIN [uStore].[dbo].[Product_Culture]PC ON PC.ProductID = OP.ProductID`r`nINNER JOIN [uStore].[dbo].[Store_Culture] SC ON SC.StoreID = O.StoreID`r`nWHERE OP.StatusID<>2 AND OP.IsDraft=0 AND O.IsCart=0 AND O.IsSaveForLater=0 AND OP.OrderHandlingStatusID IS NULL"
			$uStoreOPNULLFindForEdit = "SELECT [OrderProductID],[OrderID],[ProductID],[OrderHandlingStatusID]`r`nFROM [uStore].[dbo].[OrderProduct]`r`nwhere OrderProductID IN (OrderProductID1, OrderProductID2, OrderProductID3, Etc...)"
			#this WTF below was the original output, that lets the user look for the product type, and determine what handling status it should get
			#it was too much to ask, as Steve Case pointed out politely. very cumbersome.
			#so now we are giving the full query to change statuses
			# wtf "uStore: there are $uStoreOPNULCount problematic order products with NULL handling status (the following list is limited to 20 records):`r`n$uStoreOPNULL`r`n`r`nThis can cause discrepancies in the orders screen.`r`n" "" w "You can find them in the uStore DB using this query:`r`n$uStoreOPNULLFind`r`n`r`nOnce you have the OrderProductID, you can go to OrderProduct and change that order product`r`nto have OrderHandlingStatusID equal the relevant Pending status (for print the value is 1, for email 200, for CoD 400),`r`nusing this query in the uStore table OrderProduct, and then you will need to perform an action from the Orders screen:`r`n$uStoreOPNULLFindForEdit"
			if ($uStoreOPNULCount -gt 50) {
				$uStoreOPNULLFoundMessage = "`r`nThis diagnostics script can provide you with a list of queries that can fix this situation.`r`nHowever...`r`nThere are $uStoreOPNULCount items, and the list of queries will be too long for this log file (more than 50 items).`r`nIf you wish to see the full list of queries, then you will need to edit the code of the diagnostics script"
			}
			else {
				$uStoreOPNULLFoundMessage = "`r`n$uStoreStatusChangeWarning`r`n`r`nRunning the following query in the uStore DB will adjust the items that we know their default status (for print the value is 1, for email 200, for CoD 400):`r`n$uStoreOPNULLUpdateQuery"
			}
			wtf "uStore: there are $uStoreOPNULCount problematic order products with NULL handling status (the following list is limited to 20 records):`r`n$uStoreOPNULL`r`n" "" w "These items can cause discrepancies in the orders screen.`r`n`r`nYou can find these items with more details in the uStore DB using this query:`r`n$uStoreOPNULLFind`r`n$uStoreOPNULLFoundMessage"
		}
		else {
			wtf "uStore: there are no problematic order products with NULL handling status" "" g
		}

		Write-Output "uStore: check for problematic order products with wrong status ID"
		# $uStoreOPWrongStatus = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "select TOP (20) op.OrderHandlingStatusID, di.QueueID, op.OrderProductID, op.OrderID, op.ProductID from dbo.DeliveryItem di inner join dbo.OrderProduct op on di.OrderProductID = OP.OrderProductID and op.OrderHandlingStatusID <> di.QueueID" | Format-Table | out-string).Trim()
		$uStoreOPWrongStatus = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "SELECT DISTINCT top (20) O.EncryptedOrderId AS 'Order ID', OP.OrderProductID AS 'Item ID', OP.ProductID, O.DateOrderCreated AS 'Date order created', O.StoreID, PC.Name AS 'Prodct Name' FROM Orders O INNER JOIN OrderProduct OP ON O.OrderID = OP.OrderID INNER JOIN DeliveryItem ON DeliveryItem.OrderProductID = OP.OrderProductID AND OP.OrderHandlingStatusID <> DeliveryItem.QueueID INNER JOIN Users ON O.UserID = Users.UserID INNER JOIN [uStore].[dbo].[Doc] DO ON DO.ProductID = OP.ProductID INNER JOIN [uStore].[dbo].[DocType] DT ON DT.DocTypeID = DO.DocTypeID INNER JOIN [uStore].[dbo].[Product_Culture]PC ON PC.ProductID = OP.ProductID INNER JOIN [uStore].[dbo].[Store_Culture] SC ON SC.StoreID = O.StoreID order by DateOrderCreated asc" | Format-Table | out-string).Trim()
		if ($uStoreOPWrongStatus) {
			$WarningCount++
			# $uStoreOPWrongStatusCount = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "select COUNT (*) from dbo.DeliveryItem di inner join dbo.OrderProduct op on di.OrderProductID = OP.OrderProductID and op.OrderHandlingStatusID <> di.QueueID" | Format-Table | out-string).Trim()
			$uStoreOPWrongStatusCount = SQLValue $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -sqlText "select COUNT (1) from (select DISTINCT op.OrderHandlingStatusID, di.QueueID, op.OrderProductID, op.OrderID, op.ProductID from dbo.DeliveryItem di inner join dbo.OrderProduct op on di.OrderProductID = OP.OrderProductID and op.OrderHandlingStatusID <> di.QueueID) as ws"
			$uStoreOPWrongStatusText = $uStoreOPWrongStatus | Out-String
			# $uStoreOPWrongStatusFind = "select DISTINCT op.OrderHandlingStatusID, di.QueueID, op.OrderProductID, op.OrderID, op.ProductID from dbo.DeliveryItem di inner join dbo.OrderProduct op on di.OrderProductID = OP.OrderProductID and op.OrderHandlingStatusID <> di.QueueID"
			$uStoreOPWrongStatusFind = "SELECT DISTINCT O.EncryptedOrderId AS `"Order ID`", OP.OrderProductID AS `"Item ID`", OP.ProductID, O.CustomerID AS `"User ID`", Users.Login AS `"User login`", O.DateOrderCreated AS `"Date order created`", O.StoreID, SC.Name AS `"Store`" , PC.Name AS `"Prodct Name`"`r`nFROM Orders O INNER JOIN OrderProduct OP ON O.OrderID = OP.OrderID`r`nINNER JOIN DeliveryItem ON DeliveryItem.OrderProductID = OP.OrderProductID`r`nAND OP.OrderHandlingStatusID <> DeliveryItem.QueueID`r`nINNER JOIN Users ON O.UserID = Users.UserID`r`nINNER JOIN [uStore].[dbo].[Doc] DO ON DO.ProductID = OP.ProductID`r`nINNER JOIN [uStore].[dbo].[DocType] DT ON DT.DocTypeID = DO.DocTypeID`r`nINNER JOIN [uStore].[dbo].[Product_Culture]PC ON PC.ProductID = OP.ProductID`r`nINNER JOIN [uStore].[dbo].[Store_Culture] SC ON SC.StoreID = O.StoreID`r`norder by DateOrderCreated asc"
			#creating an update query			
			$uStoreOPWrongStatusFindQueueID = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -format "values" -sqlText "select di.QueueID from dbo.DeliveryItem di inner join dbo.OrderProduct op on di.OrderProductID = OP.OrderProductID and op.OrderHandlingStatusID <> di.QueueID" | Format-Table | out-string).Trim()
			$uStoreOPWrongStatusFindQueueID = $($uStoreOPWrongStatusFindQueueID -split "`r`n").Trim()
			$uStoreOPWrongStatusFindOrderProductID = (SQLProcess $uStoreSQL uStore "$DB_User_uStore" "$DB_Password_uStore" -format "values" -sqlText "select op.OrderProductID from dbo.DeliveryItem di inner join dbo.OrderProduct op on di.OrderProductID = OP.OrderProductID and op.OrderHandlingStatusID <> di.QueueID" | Format-Table | out-string).Trim()
			$uStoreOPWrongStatusFindOrderProductID = $($uStoreOPWrongStatusFindOrderProductID -split "`r`n").Trim()
			$uStoreOPWrongStatusUpdateQuery = ""
			$uStoreOPWrongStatusistIndex = 0
			foreach ($uStoreOPWrongStatusistItem in $uStoreOPWrongStatusFindOrderProductID) {
				$uStoreOPWrongStatusFindQueueIDNOW = $uStoreOPWrongStatusFindQueueID[$uStoreOPWrongStatusistIndex]
				if ($uStoreOPWrongStatusistItem -and $uStoreOPWrongStatusFindQueueIDNOW) {
					$uStoreOPWrongStatusUpdateQuery = "$uStoreOPWrongStatusUpdateQuery`r`nupdate dbo.OrderProduct set OrderHandlingStatusID = $uStoreOPWrongStatusFindQueueIDNOW where OrderProductID = $uStoreOPWrongStatusistItem;"						
				}
				$uStoreOPWrongStatusistIndex++
			}

			$uStoreOPWrongStatusChange = "update dbo.OrderProduct set OrderHandlingStatusID = {PUT THE QueueID HERE} where OrderProductID = {PUT THE OrderProductID HERE}"
			# wtf "uStore: there are $uStoreOPWrongStatusCount problematic order products with NULL handling status (the following list is limited to 20 records):`r`n$uStoreOPWrongStatusText`r`n" "" w "This can cause discrepancies in the orders screen.`r`n`r`nYou can find them in the uStore DB using this query:`r`n$uStoreOPWrongStatusFind`r`n`r`nThe solution is to take the QueueID and set it to the OrderHandlingStatusID:`r`n$uStoreOPWrongStatusChange"
			wtf "uStore: there are $uStoreOPWrongStatusCount problematic order products with wrong status ID (the following list is limited to 20 records):`r`n$uStoreOPWrongStatusText`r`n" "" w "These items can cause discrepancies in the orders screen.`r`n`r`nYou can find these items in the uStore DB using this query:`r`n$uStoreOPWrongStatusFind`r`n`r`n$uStoreStatusChangeWarning`r`n`r`nThe solution is to take the QueueID and set it to the OrderHandlingStatusID:`r`n$uStoreOPWrongStatusUpdateQuery"
		}
		else {
			wtf "uStore: there are no problematic order products with wrong status ID" "" g
		}
	}
}


#uStore logs contents
#if the XMPLogs is anywhere else (does not exist) then the test will be skipped as well
if (Test-Path -Path 'C:\XMPLogs') {
	#uStore: checking for "significant" log entries in uStore logs in the last X days
	if ($Components -match "[r]") {
		if ($Days) {
			$uStoreLogDaysCheck = $Days
		}
		else {
			$uStoreLogDaysCheck = 14
		}

		Write-Output "uStore: logs scan for significant items:"
		#relevant only if the folder actually exist, so:
		if (Test-Path -Path "$uStoreLogPathAdmin") {
			#we don't really care if there is or isn't a file, since we only try to retrieve files with relevant dates
			#if (Test-Path -LiteralPath "$uStoreLogPathAdminLogFile" -PathType Leaf) {
			$uStoreLogFilesChangedAdminLog = Get-ChildItem -Path $uStoreLogPathAdmin\uStore.* -Filter *.log | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-$uStoreLogDaysCheck)}
			$uStoreLogFilesChangedAdminLogCommand = "Get-ChildItem -Path $uStoreLogPathAdmin\uStore.* -Filter *.log | Where-Object {`$_.LastWriteTime -gt (Get-Date).AddDays(-$uStoreLogDaysCheck)}"
			#Write-Output $uStoreLogFilesChangedAdminLog
			$uStoreNewTriggers = ""
			$uStoreNewTriggersCount = 0
			$uStoreUpdatedTriggers = ""
			$uStoreUpdatedTriggersCount = 0
			$uStoreUpdatedSetup = ""
			$uStoreUpdatedSetupCount = 0
			$uStoreUpdatedApproval = ""
			$uStoreUpdatedApprovalCount = 0
			foreach ($file in $uStoreLogFilesChangedAdminLog) {
				#Write-Output "current file: $file"
				#Select-String -Path $file -Pattern "\?^(Trigger) \d{1,8} (was updated)$"
				#the following is an example of a grep with regular expression, including the 2 preceeding lines
				#from here:
				#https://stackoverflow.com/a/44684640/722666
				# $uStoreUpdatedTriggersFileContents = Select-String -Path $file -Pattern '^(Trigger) \d{1,8} (was updated)' -Context 2,0 | % {
				# 	"`r`n"+ $_.Context.PreContext[0] #the 2nd line above the match
				# 	"`r`n"+ $_.Context.PreContext[1] #the 1st line above the match
				# 	"`r`n"+ $_.Matches.Value + "`r`n"  #what the pattern matched
				#}

				#searching for new triggers
				Write-Output "  - Searching for new triggers"
				$uStoreNewTriggersList = ""
				# $uStoreNewTriggersList = Select-String -Path $file -Pattern '^(Trigger) \d{1,8} (was replaced by trigger).*' | ForEach-Object {$_.Matches.Value + "`r`n"} | Sort-Object | Get-Unique
				$uStoreNewTriggersList = Select-String -Path $file -Pattern '^(Trigger) \d{1,8} (was replaced by trigger).*' -Context 2,0 | % {
					"`r`n"+ $_.Context.PreContext[0] #the 2nd line above the match
					# " - "+ $_.Context.PreContext[1] #the 1st line above the match
					"`r`n"+ $_.Matches.Value + "`r`n"  #what the pattern matched
				}
				if ($uStoreNewTriggersList) {
					# $uStoreNewTriggersCount = $uStoreNewTriggersCount + ($uStoreNewTriggersList).Count
					$uStoreNewTriggersCount = ($uStoreNewTriggersCount + ($uStoreNewTriggersList).Count) / 2
					$uStoreNewTriggers += $uStoreNewTriggersList
				}

				#searching for updated triggers
				Write-Output "  - Searching for updated triggers"
				$uStoreUpdatedTriggersList = ""
				# $uStoreUpdatedTriggersList = Select-String -Path $file -Pattern '^(Trigger) \d{1,8} (was updated).*' | ForEach-Object {$_.Matches.Value + "`r`n"} | Sort-Object | Get-Unique
				$uStoreUpdatedTriggersList = Select-String -Path $file -Pattern '^(Trigger) \d{1,8} (was updated)' -Context 2,0 | % {
					 	"`r`n"+ $_.Context.PreContext[0] #the 2nd line above the match
					 	# " - "+ $_.Context.PreContext[1] #the 1st line above the match
					 	"`r`n"+ $_.Matches.Value + "`r`n"  #what the pattern matched
				}
				if ($uStoreUpdatedTriggersList) {
					# $uStoreUpdatedTriggersCount = $uStoreUpdatedTriggersCount + ($uStoreUpdatedTriggersList).Count
					$uStoreUpdatedTriggersCount = ($uStoreUpdatedTriggersCount + ($uStoreUpdatedTriggersList).Count) / 2
					$uStoreUpdatedTriggers += $uStoreUpdatedTriggersList
				}

				#searching for updated system settings
				Write-Output "  - Searching for updated system settings"
				$uStoreUpdatedSetupList = ""
				# $uStoreUpdatedSetupList = Select-String -Path $file -Pattern '^(System setup update:).*' | ForEach-Object {$_.Matches.Value + "`r`n"} | Sort-Object | Get-Unique
				$uStoreUpdatedSetupList = Select-String -Path $file -Pattern '^(System setup update:).*' -Context 2,0 | % {
					"`r`n"+ $_.Context.PreContext[0] #the 2nd line above the match
					# " - "+ $_.Context.PreContext[1] #the 1st line above the match
					"`r`n"+ $_.Matches.Value + "`r`n"  #what the pattern matched
				}
				if ($uStoreUpdatedSetupList) {
					# $uStoreUpdatedSetupCount = $uStoreUpdatedSetupCount + ($uStoreUpdatedSetupList).Count
					$uStoreUpdatedSetupCount = ($uStoreUpdatedSetupCount + ($uStoreUpdatedSetupList).Count) / 2
					$uStoreUpdatedSetup += $uStoreUpdatedSetupList
				}

				#searching for updated approval processes
				Write-Output "  - Searching for updated approval processes"
				$uStoreUpdatedApprovalsList = ""
				# $uStoreUpdatedSetupList = Select-String -Path $file -Pattern '^(Order approval process for store) \d{1,8} (was changed.)' | ForEach-Object {$_.Matches.Value + "`r`n"} | Sort-Object | Get-Unique
				$uStoreUpdatedApprovalsList = Select-String -Path $file -Pattern '^(Order approval process for store) \d{1,8} (was changed.)' -Context 2,0 | % {
					"`r`n"+ $_.Context.PreContext[0] #the 2nd line above the match
					# " - "+ $_.Context.PreContext[1] #the 1st line above the match
					"`r`n"+ $_.Matches.Value + "`r`n"  #what the pattern matched
				}
				if ($uStoreUpdatedApprovalsList) {
					# $uStoreUpdatedApprovalCount = $uStoreUpdatedApprovalCount + ($uStoreUpdatedApprovalsList).Count
					$uStoreUpdatedApprovalCount = ($uStoreUpdatedApprovalCount + ($uStoreUpdatedApprovalsList).Count) / 2
					$uStoreUpdatedApproval += $uStoreUpdatedApprovalsList
				}
			}

			$uStoreChangesMessage = "uStore: There were changes made in uStore setup in the last $uStoreLogDaysCheck days.`r`n"
			if (($uStoreNewTriggersCount -gt 0) -or ($uStoreUpdatedTriggersCount -gt 0) -or ($uStoreUpdatedSetupCount -gt 0) -or ($uStoreUpdatedApprovalCount -gt 0)) {
				$NoticeCount++
				#if we have more than 20 messages, then we only show a PowerShell command that the user can run
				$uStoreLogEntriesToCheck = 100
				$uStoreLogEntryLimitationMessage = "Full details are displayed up to $uStoreLogEntriesToCheck records. To see the full listing, use the following command in PowerShell:"
				if ($uStoreNewTriggersCount -gt 0) {
					if ($uStoreNewTriggersCount -gt $uStoreLogEntriesToCheck) {
						$uStoreNewTriggersShow = "$uStoreLogFilesChangedAdminLogCommand | foreach-object {Select-String -Path `$_ -Pattern `'^(Trigger) \d{1,8} (was replaced by trigger).*`' -Context 2,0 | % {`$_.Matches.Value} | Sort-Object | Get-Unique}"
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "new triggers created") + "`r`n$uStoreLogEntryLimitationMessage`r`n$uStoreNewTriggersShow`r`n"
					}
					else {
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "new triggers created") + "`r`n$uStoreNewTriggers"
					}
				}
				if ($uStoreUpdatedTriggersCount -gt 0) {
					if ($uStoreUpdatedTriggersCount -gt $uStoreLogEntriesToCheck) {
						$uStoreUpdatedTriggersShow = "$uStoreLogFilesChangedAdminLogCommand | foreach-object {Select-String -Path `$_ -Pattern `'^(Trigger) \d{1,8} (was updated).*`' -Context 2,0 | % {`$_.Matches.Value} | Sort-Object | Get-Unique}"
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "$uStoreUpdatedTriggersCount updated triggers") + "`r`n$uStoreLogEntryLimitationMessage`r`n$uStoreUpdatedTriggersShow`r`n"
					}
					else {
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "$uStoreUpdatedTriggersCount updated triggers") + "`r`n$uStoreUpdatedTriggers"
					}
				}
				if ($uStoreUpdatedSetupCount -gt 0) {
					if ($uStoreUpdatedSetupCount -gt $uStoreLogEntriesToCheck) {
						$uStoreUpdatedSetupShow = "$uStoreLogFilesChangedAdminLogCommand | foreach-object {Select-String -Path `$_ -Pattern `'^(System setup update:).*`' -Context 2,0 | % {`$_.Matches.Value} | Sort-Object | Get-Unique}"
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "$uStoreUpdatedSetupCount updated setup settings") + "`r`n$uStoreLogEntryLimitationMessage`r`n$uStoreUpdatedSetupShow`r`n"
					}
					else {
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "$uStoreUpdatedSetupCount updated setup settings") + "`r`n$uStoreUpdatedSetup"
					}
				}
				if ($uStoreUpdatedApprovalCount -gt 0) {
					if ($uStoreUpdatedApprovalCount -gt $uStoreLogEntriesToCheck) {
						$uStoreUpdatedApprovalShow = "$uStoreLogFilesChangedAdminLogCommand | foreach-object {Select-String -Path `$_ -Pattern `'^(Order approval process for store) \d{1,8} (was changed.)`' -Context 2,0 | % {`$_.Matches.Value} | Sort-Object | Get-Unique}"
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "$uStoreUpdatedApprovalCount approval process updates") + "`r`n$uStoreLogEntryLimitationMessage`r`n$uStoreUpdatedApprovalShow`r`n"
					}
					else {
						$uStoreChangesMessage = "$uStoreChangesMessage`r`n`r`n" + (LogTitle2 "$uStoreUpdatedApprovalCount approval process updates") + "`r`n$uStoreUpdatedApproval"
					}
				}
				wtf "$uStoreChangesMessage" "" n "You can find all the details in the uStore.* log files in the following folder:`r`n$uStoreLogPathAdmin"
			}
			else {
				wtf "uStore: There are no major setup changes found in the last $uStoreLogDaysCheck days" "" g
			}
		}
		else {
			#whoa! we cannot find the uStore admin log folder!
			#this is major!
			#well... only if we actually chose to run uStore tests, and not just ran the entire set of tests
			#so:
			if ($Components -match "[z]") {
				$ErrorMessagesCombined = "$ErrorMessagesCombined`r`nThe path $uStoreLogPathAdmin was not found"
			}
			else {
				$ErrorCount++
				wtf "The path $uStoreLogPathAdmin was not found." "" e
			}
		}
	}
}








if ($ErrorMessagesCombined) {
	$ErrorCount++
	wtf "The following programs, services and other items were expected but not found:" "$ErrorMessagesCombined`r`n" e "You are getting these messages because we ran all possible tests. This means that these errors may not be relevant for this specific server."
}

#PauseHere -Content "Press any key if you want to continue..."

#checking for various IIS services. not needed, as we are checking the main one
#invoke-command -scriptblock {iisreset /STATUS}
Write-Output ""



#show the user the commands needed in order to create a scheduled task - if he/she/it wishes to create one
#Write-Output ""
if ($Scheduled_tasks_user = "NT AUTHORITY\SYSTEM") {
	$SchedTaskCreationUser = ""
}
else {
	$SchedTaskCreationUser = "IMPORTANT: you may need to change the user account of the scheduled task to run with the user $Scheduled_tasks_user and make sure that you put a password there.`r`n"
}
$SchedTaskCreation = "$SchedTaskCreationUser You can create a scheduled task based on your current options, by running the following commands in PowerShell as an administrator.`r`nChange the parameters according to your preference. For help on the different parameters, run the script with the -h option:`r`n`r`n`$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -command `"& {$ScriptPath\ServerStatus.ps1 -Components $Components -ReportLevel hdewn -LogLocation `"C:\XMPLogs\ServerStatus`" -LogConditionLevel ewni -ScheduledTask}`"'
`$trigger =  New-ScheduledTaskTrigger -Daily -At 3am
`$principal = New-ScheduledTaskPrincipal -UserID `"NT AUTHORITY\SYSTEM`" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -Action `$action -Trigger `$trigger -TaskName `"XMPie ServerStatus Diagnostics`" -Description `"XMPie daily run of ServerStatus diagnostics. Files are saved in the folder: C:\XMPLogs\ServerStatus`" -Principal `$principal"
# Write-Output "$SchedTaskCreation"
wtf "### Creating a scheduled task ###`r`n$SchedTaskCreation" "" g


#how to create a Monitor Tool in uProduce Dashboard
$MonitorToolCreation = "You can create a uProduce Dashboard Monitor Tool task based on your current options, by running the following command in PowerShell as an administrator.`r`n$ScriptPath\ServerStatus.ps1 -MonitorCreate -Components $Components"
wtf "### Creating a uProduce Dashboard Monitor Tool ###`r`n$MonitorToolCreation" "" g


####################################################
#  writing the final report
####################################################

#we have 2 cases: if there are any ReportLevel parameters, or if there are not
#if we do not have any ReportLevel parameter, then we just spew out the entire report
if (!$ReportLevel) {
	Write-Output "A report for server $Machine`r`n" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "Errors issued: $ErrorCount" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "Warnings issued: $WarningCount" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "Notices issued: $NoticeCount" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "`r`nDate and time of running the script:`r$RunTime" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	if ($ParamsNotice) {
		Write-Output "`r`n$ParamsNotice" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	if (!$Components) {
		Write-Output "`r`n(no components were selected)" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	else {
		Write-Output "`r`nSelected components:`r`n$Components" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	Write-Output "`r`n`r`n$LineSeparatingError" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	# Write-Output "ERRORS" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	# Write-Output "$LineSeparatingError" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Get-Content $LogsFolder\$File_Prefix-Error.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "`r`n`r`n$LineSeparatingWarning" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	# Write-Output "WARNINGS" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	# Write-Output "$LineSeparatingWarning" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Get-Content $LogsFolder\$File_Prefix-Warning.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "`r`n`r`n$LineSeparatingNotice" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	# Write-Output "NOTICES" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	# Write-Output "$LineSeparatingNotice" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Get-Content $LogsFolder\$File_Prefix-Notice.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "`r`n`r`n$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "Details" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Get-Content $LogsFolder\$File_Prefix-Details.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "`r`n`r`n$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "INFO" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "$LineSeparating`n" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Get-Content $LogsFolder\$File_Prefix-Info.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "`r`n`r`n$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "GENERAL" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Write-Output "$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	Get-Content $LogsFolder\$File_Prefix-General.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
}
else {
	#header
	if ($ReportLevel -match "[h]") {
		Write-Output "A report for server $Machine`r`n" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "Script running date and time: $RunTime" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "Errors issued: $ErrorCount" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "Warnings issued: $WarningCount" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "Notices issued: $NoticeCount" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "`r`nDate and time of running the script:`r$RunTime" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		if ($ParamsNotice) {
			Write-Output "`r`n$ParamsNotice" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		}
		if (!$Components) {
			Write-Output "`r`n(no components were selected)" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		}
		else {
			Write-Output "`r`nSelected components:`r`n$Components" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		}
	}
	#errors
	if ($ReportLevel -match "[e]") {
		Write-Output "`r`n`r`n$LineSeparatingError" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		# Write-Output "ERRORS" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		# Write-Output "$LineSeparatingError" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Get-Content $LogsFolder\$File_Prefix-Error.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	#warnings
	if ($ReportLevel -match "[w]") {
		Write-Output "`r`n`r`n$LineSeparatingWarning" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		# Write-Output "WARNINGS" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		# Write-Output "$LineSeparatingWarning" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Get-Content $LogsFolder\$File_Prefix-Warning.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	#notices
	if ($ReportLevel -match "[n]") {
		Write-Output "`r`n`r`n$LineSeparatingNotice" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		# Write-Output "NOTICES" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		# Write-Output "$LineSeparatingNotice" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Get-Content $LogsFolder\$File_Prefix-Notice.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	#details
	if ($ReportLevel -match "[d]") {
		Write-Output "`r`n`r`n$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "Details" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Get-Content $LogsFolder\$File_Prefix-Details.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	#information
	if ($ReportLevel -match "[i]") {
		Write-Output "`r`n`r`n$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "INFO" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "$LineSeparating`r`n" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Get-Content $LogsFolder\$File_Prefix-Info.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
	#general
	if ($ReportLevel -match "[g]") {
		Write-Output "`r`n`r`n$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "GENERAL" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Write-Output "$LineSeparating" | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
		Get-Content $LogsFolder\$File_Prefix-General.txt | Out-File -Encoding utf8 -append $LogsFolder\$File_Prefix-FULL.txt
	}
}


if ($ErrorCount -gt 0) {
	$SummaryColor = "Red"
}
elseif ($WarningCount -gt 0) {
	$SummaryColor = "Yellow"
}
else {
	$SummaryColor = "Green"
}

Write-Host "`r`n###############################" -ForegroundColor $SummaryColor
if ($ErrorCount -eq 1){
	Write-Host "There is $ErrorCount error" -ForegroundColor $SummaryColor
}
else {
	Write-Host "There are $ErrorCount errors" -ForegroundColor $SummaryColor
}
if ($WarningCount -eq 1){
	Write-Host "There is $WarningCount warning" -ForegroundColor $SummaryColor
}
else {
	Write-Host "There are $WarningCount warnings" -ForegroundColor $SummaryColor
}
if ($NoticeCount -eq 1){
	Write-Host "There is $NoticeCount notice" -ForegroundColor $SummaryColor
}
else {
	Write-Host "There are $NoticeCount notices" -ForegroundColor $SummaryColor
}
Write-Host "###############################`r`n" -ForegroundColor $SummaryColor

Write-Host "`r`n#########" -ForegroundColor $SummaryColor
Write-Host "# DONE! #" -ForegroundColor $SummaryColor
Write-Host "#########`r`n" -ForegroundColor $SummaryColor


### saving the final report
#only saving the final report if LogConditionLevel is empty or the relevant levels have events
#LogConditionLevel
#by default, we ARE writing a report file
$WriteReportFile = 'Yes'
#and now we check if we should change our decision, so we change the default to No and start checking
if ($LogConditionLevel) {
	#if the log level is Information, then we have a log file regardless of the following conditions
	if ($LogConditionLevel -notmatch "[i]") {
		if ((($LogConditionLevel -match "[n]") -and ($NoticeCount -gt 0)) ) {
			$WriteReportFile = 'Yes'
		}
		if (($LogConditionLevel -match "[w]") -and ($WarningCount -gt 0)) {
			$WriteReportFile = 'Yes'
		}
		if (($LogConditionLevel -match "[e]") -and ($ErrorCount -gt 0)) {
			$WriteReportFile = 'Yes'
		}
	}
}


if ($WriteReportFile -eq 'Yes') {
	Write-Output "Final report was saved as:"
	if (!$LogLocation -and !$MonitorCreate) {
		Copy-Item  $LogsFolder\$File_Prefix-FULL.txt $ScriptPath\$File_Prefix.txt
		Write-Output "$ScriptPath\$File_Prefix.txt"
	}
	else {
		if ($MonitorCreate -or $MonitorRun) {
			Copy-Item  $LogsFolder\$File_Prefix-FULL.txt $XMPiePathBasic\XMPieDashboard\Monitoring\$File_Prefix_Monitor.txt
			Write-Output "$XMPiePathBasic\XMPieDashboard\Monitoring\$File_Prefix_Monitor.txt"
		}
		else {
			Copy-Item  $LogsFolder\$File_Prefix-FULL.txt $LogLocation\$File_Prefix.txt
			Write-Output "$LogLocation\$File_Prefix.txt"
		}
	}
}
#if we are not writing a log file, then anyway we are just deleting the logs folder without the above copy section
Remove-Item -Recurse -Force $LogsFolder
#presenting the option to continue only if the script is running as a pop-up
if (!$MonitorRun -and !$ScheduledTask -and ( (((ShellOrClick) -eq "click") -and (!$RunSilent)) -or ($PS1orEXE -eq "exe") )) {
	PauseHere -Content "Press any key to continue..."
}

exit

#the PS2EXE conversion script that is used in order to create the EXE file
#put the following lines (uncommented) in a PS1 file in the folder where the ServerStatus script is, and an EXE file will be created
# #Get the location of the script (where it is running from)
# if ($MyInvocation.MyCommand.CommandType -eq "ExternalScript") {
	# $ScriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
# }
# else {
	# $ScriptPath = Split-Path -Parent -Path ([Environment]::GetCommandLineArgs()[0])
    # if (!$ScriptPath){
		# $ScriptPath = "."
	# }
# }

# $Version = Get-Date -UFormat "%Y.%m.%d"
# $VersionDashes = Get-Date -UFormat "%Y-%m-%d"
# $Year = Get-Date -UFormat "%Y"
# $Copyright = "Copyright © $Year XMPie Inc."
# $InputFile = "$ScriptPath\ServerStatus.ps1"
# $OutputFile = "$ScriptPath\ServerStatus-$VersionDashes.exe"
# $Icon = "$ScriptPath\XMPie.ico"
# $Title = "Server Status Diagnostics Tool"
# $Product = "ServerStatus"
# $Company = "XMPie"

# # & powershell.exe "$ScriptPath\ps2exe.ps1 -inputFile $InputFile -outputFile $OutputFile -version $Version -icon $Icon -title $Title -company $Company -noConfigfile -requireAdmin"
# & powershell.exe "$ScriptPath\ps2exe.ps1 -inputFile $InputFile -outputFile $OutputFile -noConfigfile -requireAdmin -icon '$Icon' -title '$Title' -company '$Company'  -version '$Version' -copyright '$Copyright' -product '$Product'"