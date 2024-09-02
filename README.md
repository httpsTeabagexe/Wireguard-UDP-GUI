# Working script

## Manually run script in Powershell

if your .conf looks like this: 
```
[Interface]
PrivateKey = PRIVATEKEY
ListenPort = LISTENPORT
Address = IPV4, IPV6
DNS = 1.1.1.1
MTU = 1234

[Peer]
PublicKey = PUBLICKEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ENDPOINT_IP:ENDPOINT_PORT

```
then disable wg connection, change you LISTEN_PORT from (e.g) 12345 -> 12346
and put it in script below

```
$wgListenPort = LISTENPORT
$wgIP = "ENDPOINT_IP"
$wgPORT = ENDPOINT_PORT

$EndPoints = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($wgIP)), $wgPORT) 
$Socket = New-Object System.Net.Sockets.UDPClient $wgListenPort
$SendMessage = $Socket.Send([Text.Encoding]::ASCII.GetBytes(":)"), 2, $EndPoints) 
$Socket.Close()

```

# NOT WORKING AS OF 2 SEPT 2024

## Wireguard-UDP-GUI
This script is a graphical user interface (GUI) application for managing a WireGuard VPN connection. It allows users to import WireGuard configuration files, start and stop the WireGuard process, and send UDP packets to a specified IP address and port. The script also includes a log window for displaying status messages and error messages.

![image](https://github.com/user-attachments/assets/699b329a-5dcd-4257-9ed6-74fec833f860)



## Features:
Import WireGuard configuration files
Start and stop the WireGuard process
Send UDP packets to a specified IP address and port
Display status messages and error messages in a log window


## Requirements:
- .NET Framework 4.5 or later
- WireGuard installed on the system
- A WireGuard configuration file


## Usage:
GUI:
- Run .ps1 file as admin(!)
- Import config
- Press "Start WireGuard"
  
CLI:
- Download files and save them in same direction.
- Open a PowerShell window as an administrator.
- Run the script with the following command: .\WireGuardManager.ps1


## Notes:
- The script requires administrative privileges to run.
- The script assumes that the WireGuard executable is located at C:\Program Files\WireGuard\WireGuard.exe.
- The script does not handle errors gracefully. In a production environment, you should add more error handling to make the script more robust.
- The script could benefit from some documentation to explain what it does and how to use it.
