function Get-SrvSysVersion
{
<#

.SYNOPSIS
	This function will list the version of Srv.sys and check if its been patched against MS17-010.

.DESCRIPTION
	The script will use WMI to query the version of srv.sys and check the version against a known
    patched version.

.PARAMETER ActiveDirectory
	Queries Active Directory for all Windows computers with a user specified number of days since
    lastLogon.

.PARAMETER Credentials
    Pops up a login box to change your scan credentials. Usefull for scanning other domains.

.PARAMETER ComputerName
	A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

.PARAMETER DomainServer
    The domain to query if using the ActiveDirectory parameter.
    Default Value: $ENV:USERDOMAIN (current domain)

.PARAMETER Jobs
	Number of jobs to spawn, be careful this is the total number of PowerShell processes that will
    be open. Too high a value will use a lot of memory..
	Default Value = 30

.EXAMPLE
	$Servers = Get-Content "C:\ServerList.txt"
	.\Get-SrvSysVersion.ps1 -ComputerName $Servers

	This example will return the last logon information from all the servers in the
    C:\ServerList.txt file.

    Computer        : YTMKBB0031KMWCB
    OS              : Microsoft Windows 7 Enterprise  LDR (Build Number 7601)
    ExpectedVersion : 6.1.7601.23689
    ActualVersion   : 6.1.7601.23517
    Patched         : False
    UpTime          : 165
    Message         :
    RunspaceId      : bfb9c738-44c6-44b1-a26e-6069fc0a4f48

.EXAMPLE
	.\Get-SrvSysVersion.ps1 -ActiveDirectory 10 | select Computer,OS,Patched,ExpectedVersion,
    ActualVersion,UpTime,Message | Export-Csv C:\tmp\SrvSys.csv

	This example will return the Srv.sys information from all the servers that have logged in
    to AD in the past 10 days and export it to csv.

.EXAMPLE
	.\Get-SrvSysVersion.ps1 -ActiveDirectory 10 -Jobs 50 -DomainServer Contoso.local -Credential

	This example will return the Srv.sys information from all the servers in Contoso.local that
    have logged in, in the past 10 day and prompt for credentials.

.LINK

.NOTES
	Author: Rob Antonucci
	Date: 08/29/2017
#>

 param (
    [int]$ActiveDirectory = 0,
    [array]$ComputerName = "localhost",
    [switch]$Credential = $false,
    [string]$DomainServer = $($ENV:USERDOMAIN),
    [array]$Exclude = $false,
    [int]$Jobs = 30
 )

[reflection.assembly]::LoadWithPartialName("System.Version")

if ($Credential) {
    $Creds = Get-Credential
}


if ($ActiveDirectory) {
    # get the date for n days ago
    $time = (Get-Date).Adddays(-($($ActiveDirectory)))

    # Show servers and workstations
    $ADFilter = {(OperatingSystem  -Like 'Windows*') -and (LastLogonDate -gt $time)}

    $ComputerName = Get-ADComputer -Server $DomainServer -Filter $ADFilter
    $ComputerName = $ComputerName.DNSHostName | Sort-Object
} # end if ($ActiveDirectory)

$ComputersLeft = $ComputerName.count

# Kill existing Jobs
Get-Job | Remove-Job -Force

foreach ($Computer in $ComputerName) {
    $Job = Start-Job -Name $Computer -ArgumentList $Computer,$Credential,$Creds -ScriptBlock {
        param($Computer,$Credential,$Creds)
            # Get Srv.sys version
			$fileVersion = New-Object System.Version("0.0.0000.00000")
			$expectedVersion = New-Object System.Version("0.0.0000.00000")
			$patched = "Unknown"
			$msg = ""
			$upTime = ""
			try {

                if ($Credential) {
                    $os = Get-WmiObject -class Win32_OperatingSystem -ComputerName $Computer -Credential $Creds -ErrorAction Stop
                }
                else {
                    $os = Get-WmiObject -class Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop
                }
                $upTime = $os.LastBootUpTime
                $upTime = [Management.ManagementDateTimeConverter]::ToDateTime($upTime)
                $upTime = $((Get-Date) - $upTime).Days
                $osName = $os.Caption -replace ",",""
                $osDrive = $os.SystemDrive
                $systemDir = $($os.SystemDirectory -replace "\\", "\\").split(":")[1]
                if ($Credential) {
                    $versionInfo = Get-WMIObject -ComputerName $Computer -Query "SELECT * FROM CIM_DataFile WHERE Drive ='$osDrive' AND Path='$systemDir\\drivers\\' AND FileName='srv' AND Extension='sys'" -Credential $Creds -ErrorAction Stop| select Version
                }
                else {
                    $versionInfo = Get-WMIObject -ComputerName $Computer -Query "SELECT * FROM CIM_DataFile WHERE Drive ='$osDrive' AND Path='$systemDir\\drivers\\' AND FileName='srv' AND Extension='sys'" -ErrorAction Stop | select Version
                }
                if ($versionInfo) {
                    $versionString = $versionInfo.version
                    try {
                        # Get rid of any other version text
                        $versionString = $versionInfo.version.split(" ")[0]
                        $fileVersion = New-Object System.Version($versionString)
                    }
                    Catch {
                        $fileVersion = New-Object System.Version($versionString)
                    }
                }
                else {
                    $msg = "Couldn't get version info."
                }
            } # end try WMI
            Catch {
                $msg = $_.Exception.Message.replace("`n","").replace("`r","")
            }
                if ($os) {
                    if ($osName.Contains("Vista") -or ($osName.Contains("2008") -and -not $osName.Contains("R2")))
                        {
                        if ($versionString.Split('.')[3][0] -eq "1")
                            {
                            $currentOS = "$osName GDR"
                            $expectedVersion = New-Object System.Version("6.0.6002.19743")
                            }
                        elseif ($versionString.Split('.')[3][0] -eq "2")
                            {
                            $currentOS = "$osName LDR"
                            $expectedVersion = New-Object System.Version("6.0.6002.24067")
                            }
                        else
                            {
                            $currentOS = "$osName"
                            $expectedVersion = New-Object System.Version("99.9.9999.99999")
                            }
                        }
                    elseif ($osName.Contains("Windows 7") -or ($osName.Contains("2008 R2")) -or ($os.Version -eq "6.1.7601"))
                        {
                        $currentOS = "$osName LDR"
                        $expectedVersion = New-Object System.Version("6.1.7601.23689")
                        }
                    elseif ($osName.Contains("Windows 8.1") -or $osName.Contains("2012 R2"))
                        {
                        $currentOS = "$osName LDR"
                        $expectedVersion = New-Object System.Version("6.3.9600.18604")
                        }
                    elseif ($osName.Contains("Windows 8") -or $osName.Contains("2012"))
                        {
                        $currentOS = "$osName LDR"
                        $expectedVersion = New-Object System.Version("6.2.9200.22099")
                        }
                    elseif ($osName.Contains("Windows 10"))
                        {
                        if ($os.BuildNumber -eq "10240")
                            {
                            $currentOS = "$osName TH1"
                            $expectedVersion = New-Object System.Version("10.0.10240.17319")
                            }
                        elseif ($os.BuildNumber -eq "10586")
                            {
                            $currentOS = "$osName TH2"
                            $expectedVersion = New-Object System.Version("10.0.10586.839")
                            }
                        elseif ($os.BuildNumber -eq "14393")
                            {
                            $currentOS = "$($osName) RS1"
                            $expectedVersion = New-Object System.Version("10.0.14393.953")
                            }
                        elseif ($os.BuildNumber -eq "15063")
                            {
                            $currentOS = "$osName RS2"
                            $msg = "No need to Patch. RS2 is released as patched."
                            $patched = $true
                            }
                        else
                            {
                            $currentOS = "$osName"
                            $expectedVersion = New-Object System.Version("99.9.9999.99999")
                            $msg = "Unable to determine OS applicability, please verify vulnerability state manually."
                            }
                        }
                    elseif ($osName.Contains("2016"))
                        {
                        $currentOS = "$osName"
                        $expectedVersion = New-Object System.Version("10.0.14393.953")
                        }
                    elseif ($osName.Contains("Windows XP"))
                        {
                        $currentOS = "$osName"
                        $expectedVersion = New-Object System.Version("5.1.2600.7208")
                        }
                    elseif ($osName.Contains("Server 2003"))
                        {
                        $currentOS = "$osName"
                        $expectedVersion = New-Object System.Version("5.2.3790.6021")
                        }
                    else
                        {
                        $currentOS = "$osName"
                        $msg = "Unable to determine OS applicability, please verify vulnerability state manually."
                        $expectedVersion = New-Object System.Version("99.9.9999.99999")
                        }
                $fullOS = "$currentOS (Build Number $($os.BuildNumber))"
                }
                else {
                    $fullOS = "Unknown"
                }  #end if ($os)
                If ($($fileVersion.CompareTo($expectedVersion)) -lt 0)
                    {
                    $patched = $false
                    }
                else{
                    if ($($fileVersion.CompareTo($(New-Object System.Version("0.0.0000.00000")))) -gt 0) {
                    $patched = $true
                    }
                }

        $details = @($Computer,$fullOS,$expectedVersion,$fileVersion,$patched,$upTime,$msg)
		return $details

    } # end $Job = Start-Job -Name $Computer -ArgumentList $Computer -ScriptBlock

    $ComputersLeft --

    # Dont run too many jobs at once
    $TotalJobs = (Get-Job).count
    if (($TotalJobs -eq $Jobs) -or ($ComputersLeft -eq 0)) {
        $AllJobs = Get-Job
        foreach ($Job in $AllJobs) {
            if ($Job.State -eq 'Running') {
                $Job | Wait-Job -Timeout 60 | Out-Null
            }
			if ($Job.State -eq 'Completed') {
				$details = $Job | Receive-Job
			}
			else{
				Write-Warning "$($Job.Name) timed out."
				$details = @($Job.Name,"Unknown",$(New-Object System.Version("0.0.0000.00000")),$(New-Object System.Version("0.0.0000.00000")),"Unknown","","Job timed out.")
			}
			$Job | Remove-Job -Force
			$SrvSys = New-Object -TypeName PSObject
			$SrvSys | Add-Member -MemberType NoteProperty -Name Computer -Value $details[0]
			$SrvSys | Add-Member -MemberType NoteProperty -Name OS -Value $details[1]
			$SrvSys | Add-Member -MemberType NoteProperty -Name ExpectedVersion -Value $details[2]
			$SrvSys | Add-Member -MemberType NoteProperty -Name ActualVersion -Value $details[3]
			$SrvSys | Add-Member -MemberType NoteProperty -Name Patched -Value $details[4]
			$SrvSys | Add-Member -MemberType NoteProperty -Name UpTime -Value $details[5]
			$SrvSys | Add-Member -MemberType NoteProperty -Name Message -Value $details[6]
            $SrvSys
        } #end foreach ($Job in $AllJobs)
    } #end if (($TotalJobs -eq $Jobs) -or ($ComputersLeft -eq 0))
} #end foreach ($Computer in $ComputerName)
#$ComputersArray | Select Computer, OS, ExpectedVersion, ActualVersion, Patched, Message
}#end function
