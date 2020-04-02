<#
.SYNOPSIS
   Creates firewall rules for Teams.
.DESCRIPTION
Required as Teams resides in user profiles and GPO deployment of rules is not supported for executables in this method.
This script creates allow rules by default for teams.exe for each user found on a machine and creates block rules to block peer to peer traffic between users who are on a VPN.
#>
 
$users = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') -Exclude 'Public', 'ADMINI~*'
if ($null -ne $users) {
    foreach ($user in $users) {
        $progPath = Join-Path -Path $user.FullName -ChildPath "AppData\Local\Microsoft\Teams\Current\Teams.exe"
        if (Test-Path $progPath) {
            if (-not (Get-NetFirewallApplicationFilter -Program $progPath -ErrorAction SilentlyContinue)) {
                $ruleNameAllow = "Allow Teams.exe for user $($user.Name)"
                             $ruleNameBlock = "Block Teams.exe VPN Peer to Peer for user $($user.Name)"
                "UDP", "TCP" |  ForEach-Object { New-NetFirewallRule -DisplayName $ruleNameAllow -Direction Inbound -Profile Any -Program $progPath -Action Allow -Protocol $_ }
                             "UDP", "TCP" |  ForEach-Object { New-NetFirewallRule -DisplayName $ruleNameAllow -Direction Outbound -Profile Any -Program $progPath -Action Allow -Protocol $_ }
                             "UDP", "TCP" | ForEach-Object { New-NetFirewallRule -DisplayName $ruleNameBlock -Direction Inbound -Profile Any -Program $progPath -Action Block -Protocol $_ -LocalAddress VPNSUBNETSHERE -RemoteAddress VPNSUBNETSHERE,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8 }
                             "UDP", "TCP" | ForEach-Object { New-NetFirewallRule -DisplayName $ruleNameBlock -Direction Outbound -Profile Any -Program $progPath -Action Block -Protocol $_ -LocalAddress VPNSUBNETSHERE -RemoteAddress VPNSUBNETSHERE,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8 }
 
                Clear-Variable ruleNameAllow
                Clear-Variable rulenameBlock
            }
        }
        Clear-Variable progPath
    }
}
