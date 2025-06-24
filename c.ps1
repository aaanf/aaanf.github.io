$confirm = Read-Host "[*] only for current user?"
$onlyCurrentUser = $confirm -in @('Y', 'Yes', 'yes', 'YES', 'y')

function Generate-Password {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    -join ((1..64) | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
}

try {
    $rdpPort = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name PortNumber | Select-Object -ExpandProperty PortNumber
} catch {
    $rdpPort = 3389
}

$computers = $env:COMPUTERNAME
$domain = $env:USERDOMAIN
try {
    $publicIp = (Invoke-RestMethod -Uri "http://ifconfig.me/ip").Trim()
} catch {
    $publicIp = "unknown"
}

$results = @()

if ($onlyCurrentUser) {
    $user = $env:USERNAME
    $password = Generate-Password
    net user $user $password
    $results += "${publicIp}:${rdpPort}@${computers}\$user;$password"
} else {
    $accounts = @('HomeGroupUser', 'DefaultUser')
    foreach ($acc in $accounts) {
        $password = Generate-Password
        net user $acc $password | Out-Null
        $results += "${publicIp}:${rdpPort}@${computers}\$acc;$password"
    }
}

Write-Output "# computer: $computers/$domain"
Write-Output ""
Write-Output "# all internet adapters"
Get-NetIPAddress | Where-Object { $_.AddressFamily -in @('IPv4', 'IPv6') -and $_.IPAddress -notlike '169.254*' } | ForEach-Object {
    "$($_.IPAddress) ($($_.InterfaceAlias))"
}
Write-Output ""
Write-Output "# result"
$results | ForEach-Object { $_ }
