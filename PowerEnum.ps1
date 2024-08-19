<#
references
https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1
https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASps1/winPEAS.ps1
https://serverfault.com/revisions/1111447/1
#>

function Print-CringeAscii {
    $asciiArt = @"
    ____                          ______                    
   / __ \____ _      _____  _____/ ____/___  __  ______ ___ 
  / /_/ / __ \ | /| / / _ \/ ___/ __/ / __ \/ / / / __ `__ \
 / ____/ /_/ / |/ |/ /  __/ /  / /___/ / / / /_/ / / / / / /
/_/    \____/|__/|__/\___/_/  /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                            
"@

    Write-Host $asciiArt -ForegroundColor Red
    Write-Host "written by 0xCh33z" -ForegroundColor White
    Write-Host ""
}

function Print-Separator([string]$sectionName) {   
    $separatorOne = "<-_,.-'~'-.,__,.-'~'-.,__,.-'{ "
    $separatorTwo = " }'-.,__,.-'~'-.,__,.-'~'-.,_->"
    $separatorThree = ("`/^(o.o)^\" * 9) + "`n"

    write $separatorThree
    write $separatorOne$sectionName$separatorTwo
    write ""

    write $separatorThree

    write $separatorThree | Out-Null
}

function Print-Timestamp {
    $getDate = Get-Date
    write "You ran this script on $getDate.`n`n"
}

function Get-SystemInfo {
    #Get Username
    write "[+] Username:`t`t $env:USERNAME"

    #Get Computername
    write "[+] Hostname:`t`t $env:COMPUTERNAME"

    #Get Domain
    $domain = (gwmi -ClassName Win32_ComputerSystem).Domain
    write "[+] Domain:`t`t $domain"

    #Get Windows Build
    $osName = gwmi -class Win32_OperatingSystem | select -ExpandProperty Caption | foreach { $_.replace('Microsoft','').trim() }
    $osBuild = gwmi -class Win32_OperatingSystem | select -ExpandProperty BuildNumber | foreach { $_.trim() }
    $osVersion = gwmi -class Win32_OperatingSystem | select -ExpandProperty Version | foreach { $_ -replace('\.\d+$','').trim() }
    $osArchitecture = (gwmi -ClassName Win32_OperatingSystem).OSArchitecture
    write "[+] Operating System:`t $osName $osArchitecture (Version: $osVersion, Build: $osBuild)"
    write ""
}

function Get-LocalGroups {
    $localGroups = whoami /groups |
        where { $_ -notmatch 'GROUP INFORMATION|-----------------' } |
        Out-String

    Print-Separator "Groups"
    write $localGroups
}

function Get-Privileges {
    $privileges = whoami /priv |
        foreach { $_ -replace '(State|Enabled|Disabled|========|PRIVILEGES INFORMATION|----------------------)\s*$', '' } |
        Out-String

    Print-Separator "Privileges"
    write $privileges
}

function Get-LocalUsers {
    $localUsers = Get-LocalUser |
        select -ExpandProperty Name |
        Out-String

    Print-Separator "Local Users"
    write $localUsers
}

function Get-SMBShares {
    $smbShares = Get-SMBShare | Out-String

    Print-Separator "SMB Shares"
    write $smbShares
}

function Get-AutoRunKey {
    $autoruns = gwmi Win32_StartupCommand | select Name, Command, Location, User | FL |
        Out-String

    Print-Separator "Autorun Applications"
    write $autoruns
}

function Get-RunningProcesses {
    $runningProcesses = Get-Process |
        select ProcessName,Id |
        Out-String

    Print-Separator "Running Processes"
    write $runningProcesses
}

function Get-RunningServices {
    $runningServices = gwmi -ClassName win32_service |
        Select Name,State,PathName |
        where {$_.State -like 'Running'} |
        Out-String

    Print-Separator "Running Services"
    write $runningServices
}

function Get-UnquotedServicePaths {
    $unquotedServicePaths = gwmi -Class Win32_Service |
        where {
            $_.PathName -match "\s" -and
            $_.PathName -notmatch " -" -and
            $_.PathName -notmatch "`"" -and
            $_.PathName -notmatch ":\\Windows\\" -and
            ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and
            ($_.State -eq "Running" -or $_.State -eq "Stopped")
        } |
        select Name, PathName, StartMode, State
    
    Print-Separator "Unquoted Service Paths"

    if ($unquotedServicePaths.length -le 1) {
        write "No unquoted service paths found."
        write ""
    } else {
        write $unquotedServicePaths
        }
}


function Get-WifiCredentials {
    Print-Separator "Credentials"
    write "[+] Wi-Fi:`n"

    $profileNames = netsh wlan show profile |
        findstr '   : ' |
        foreach { $_ -replace '.*Profile\s+:\s|Profiles on interface.+', '' }

    foreach ($profileName in $profileNames) {
        $profileDetails = netsh wlan show profile name="$profileName" key=clear

        # Extract SSID name and Key Content
        $ssid = ($profileDetails |
            sls -Pattern 'SSID name\s*:\s*(.*)' |
            foreach { $_.Matches.Groups[1].Value.Trim() })

        $keyContent = ($profileDetails |
            sls -Pattern 'Key Content\s*:\s*(.*)' |
            foreach { $_.Matches.Groups[1].Value.Trim() })

        # Output the SSID and Key Content if both are present
        if ($ssid -and $keyContent) {
            write "`t`tSSID: $ssid"
            write "`t`tPassword: $keyContent"
            write ""
        }
    }
}

function Get-ActiveConnections {
    Print-Separator "Active Connections"
    $activeConnections = netstat -ano |
        foreach { $_ -replace 'Active Connections', ''} |
        Out-String

    write $activeConnections
}

function Get-NetworkInterfaces {
    Print-Separator "Network Interfaces"
    $networkInterfaces = ipconfig /all |
        Out-String

    write $networkInterfaces
}

function Get-HostsFile {
    Print-Separator "Hosts File"
    $hostsFile = gc "$env:windir\System32\drivers\etc\hosts" |
        Out-String

    write $hostsFile
}

function Get-RoutingTable {
    Print-Separator "Routing Table"
    $routingTable = route print |
        Out-String

    write $routingTable
}

function Get-InterestingFiles {
    Print-Separator "Potential Interesting Files"
    $interestingFiles = Get-ChildItem "C:\Users\" -Recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue |
        foreach { $_.FullName } |
        Out-String

    write $interestingFiles
}

function Get-PowerShellHistory {
    Print-Separator "PowerShell History"
    $powershellHistory = gc (Get-PSReadLineOption).HistorySavePath | Out-String
    write $powershellHistory
}

function Get-ScheduledTasks {
    Print-Separator "Scheduled Tasks"
    write "# Excludes Tasks with Base TaskPath of '\Microsoft\'"
    $scheduledTasks = Get-ScheduledTask | 
        where {$_.TaskPath -notlike "\Microsoft*"} | 
        ft TaskName,TaskPath,State

        write $scheduledTasks
}

function Get-InstalledApplications {  # Thanks, Ace https://serverfault.com/revisions/1111447/1
    Print-Separator "Installed Applications"
    
    $keys = '', '\Wow6432Node'
    $NameRegex = ''
    
    foreach ($key in $keys) {
        try {
            $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
            $apps = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
        } catch {
            continue
        }

        foreach ($app in $apps) {
            $program = $reg.OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
            $name = $program.GetValue('DisplayName')
            
            if ($name -and $name -match $NameRegex) {
                [pscustomobject]@{
                    AppName          = $name
                    AppVersion       = $program.GetValue('DisplayVersion')
                    Publisher        = $program.GetValue('Publisher')
                    UninstallString  = $program.GetValue('UninstallString')
                    Architecture     = if ($key -eq '\Wow6432Node') { '64-bit' } else { '32-bit' }
                    RegKeyPath       = $program.Name
                }
            }
        }
    }
}



# Execute Functions
Print-CringeAscii
Print-Timestamp
Get-SystemInfo
Get-RunningProcesses
Get-RunningServices
Get-UnquotedServicePaths
Get-LocalGroups
Get-Privileges
Get-LocalUsers
Get-SMBShares
Get-AutoRunKey
Get-ScheduledTasks
Get-HostsFile
Get-WifiCredentials
Get-ActiveConnections
Get-NetworkInterfaces
Get-RoutingTable
Get-InterestingFiles
Get-InstalledApplications | Out-String
Get-PowerShellHistory
