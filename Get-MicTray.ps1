 param (
    [string]$DomainServer = $($ENV:USERDOMAIN),
    [array]$ComputerName = "localhost",
    [switch]$Credential = $false,
    [int]$ActiveDirectory = 0,
    [int]$Jobs = 30
 )

 if ($Credential) {
    $Creds = Get-Credential
}


if ($ActiveDirectory) {
    # get the date for n days ago
    $time = (Get-Date).Adddays(-($($ActiveDirectory)))
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
            try {
                $msg = ""
                $path = ""
                $size = ""
                $os = Get-WmiObject -class Win32_OperatingSystem -ComputerName $Computer -Credential $Creds -ErrorAction Stop
                $osName = $os.Caption -replace ",",""
                $osDrive = $os.SystemDrive
                $WMIQuery = "SELECT * FROM CIM_DataFile WHERE Drive ='$osDrive' AND Path='\\Users\\Public\\' AND FileName='MicTray' AND Extension='log'"
                $fileInfo = Get-WMIObject -ComputerName $Computer -Credential $Creds -Query $WMIQuery -ErrorAction Stop | Select Size,Name
                if ($fileInfo) {
                    $path = "\\$Computer\$($osDrive -replace ":","$")\Users\Public\MicTray.log"
                    $size = $fileInfo.Size
                }
                else {
                    $msg = "File doesn't exist."
                }
            } #end try WMI
            Catch {
                $msg = $_.Exception.Message.replace("`n","").replace("`r","")
            } #end Catch
        
        $MicTray = New-Object -TypeName PSObject
        $MicTray | Add-Member -MemberType NoteProperty -Name Computer -Value $Computer
        $MicTray | Add-Member -MemberType NoteProperty -Name Path -Value $path
        $MicTray | Add-Member -MemberType NoteProperty -Name Size -Value $size
        $MicTray | Add-Member -MemberType NoteProperty -Name Message -Value $msg
        return $MicTray

    } # end $Job = Start-Job -Name $Computer -ArgumentList $Computer -ScriptBlock
    
    $ComputersLeft --
    
    # Dont run too many jobs at once
    $TotalJobs = (Get-Job).count
    if (($TotalJobs -eq $Jobs) -or ($ComputersLeft -eq 0)) {
        $AllJobs = Get-Job
        foreach ($Job in $AllJobs) {
            if ($Job.State -eq 'Running') {
                $Job | Wait-Job -Timeout 30 | Out-Null
            }
            $MicTray = $Job | Receive-Job
            $Job | Remove-Job -Force
            Write-Output $MicTray
        } #end foreach ($Job in $AllJobs)
    } #end if (($TotalJobs -eq $Jobs) -or ($ComputersLeft -eq 0))
} #end foreach ($Computer in $ComputerName)
#$ComputersArray | Select Computer, OS, ExpectedVersion, ActualVersion, Patched, Message