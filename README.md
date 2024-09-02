# Wireguard-UDP-GUI
This script is a graphical user interface (GUI) application for managing a WireGuard VPN connection. It allows users to import WireGuard configuration files, start and stop the WireGuard process, and send UDP packets to a specified IP address and port. The script also includes a log window for displaying status messages and error messages.


## Features:
Import WireGuard configuration files
Start and stop the WireGuard process
Send UDP packets to a specified IP address and port
Display status messages and error messages in a log window


## Requirements:
.NET Framework 4.5 or later
WireGuard installed on the system
A WireGuard configuration file


## Usage:
Download the script and save it to a file (e.g., WireGuardManager.ps1).
Open a PowerShell window as an administrator.
Run the script with the following command: .\WireGuardManager.ps1


## Notes:
The script requires administrative privileges to run.
The script assumes that the WireGuard executable is located at C:\Program Files\WireGuard\WireGuard.exe.
The script does not handle errors gracefully. In a production environment, you should add more error handling to make the script more robust.
The script could benefit from some documentation to explain what it does and how to use it.
