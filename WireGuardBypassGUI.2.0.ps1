# Check if running with administrative privileges
# if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
#     Write-Host "This script requires administrative privileges. Please run it as an administrator."
#     exit
# }

# Load necessary assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName System.Windows.Forms

# Load XAML and Create Form
[xml]$Xaml = Get-Content -Path ".\MainWindow.2.0.xaml"
if ($null -eq $Xaml) {
    Write-Error "Failed to load XAML file."
    return
}
$Reader = New-Object System.Xml.XmlNodeReader $Xaml
$Form = [Windows.Markup.XamlReader]::Load($Reader)
if ($null -eq $Form) {
    Write-Error "Failed to create form from XAML."
    return
}

# Bind controls
$ListenPortTextBox = $Form.FindName("ListenPortTextBox")
$ServerIPTextBox = $Form.FindName("ServerIPTextBox")
$ServerPortTextBox = $Form.FindName("ServerPortTextBox")
$ConfigPathTextBox = $Form.FindName("ConfigPathTextBox")
$PrivateKeyTextBox = $Form.FindName("PrivateKeyTextBox")
$ImportConfigButton = $Form.FindName("ImportConfigButton")
$StartWireGuardButton = $Form.FindName("StartWireGuard")
$StopWireGuardButton = $Form.FindName("StopWireGuard")
$StatusTextBlock = $Form.FindName("StatusTextBlock")
$UseSystemProxyCheckBox = $Form.FindName("UseSystemProxyCheckBox")  # Bind the CheckBox control

# Event handler for UseSystemProxyCheckBox
$UseSystemProxyCheckBox.Add_Click({
    $useSystemProxy = $UseSystemProxyCheckBox.IsChecked
    if ($useSystemProxy) {
        Append-Log "System proxy enabled."
        # Add code to enable system proxy in WireGuard config or system settings
    } else {
        Append-Log "System proxy disabled."
        # Add code to disable system proxy in WireGuard config or system settings
    }
})

# Event handler for ImportConfigButton
$ImportConfigButton.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "WireGuard Config Files (*.conf)|*.conf"
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $configPath = $openFileDialog.FileName
        $ConfigPathTextBox.Text = $configPath

        $configContent = Get-Content -Path $configPath
        $privateKeyFound = $false

        foreach ($line in $configContent) {
            if ($line -match "^Endpoint\s*=\s*(?<ip>[\d\.]+):(?<port>\d+)") {
                $ServerIPTextBox.Text = $matches['ip']
                $ServerPortTextBox.Text = $matches['port']
            } elseif ($line -match "^ListenPort\s*=\s*(?<port>\d+)") {
                $ListenPortTextBox.Text = $matches['port']
            } elseif ($line -match "^PrivateKey\s*=\s*(?<key>[a-zA-Z0-9+/=]+)") {
                $PrivateKeyTextBox.Password = $matches['key']
                $privateKeyFound = $true
            }
        }

        if (-not $privateKeyFound) {
            Append-Log "Warning: Private key not found in the configuration file."
        } else {
            Append-Log "Configuration imported successfully."
        }
    }
})

# Event handler for StartWireGuardButton
$StartWireGuardButton.Add_Click({
    $wgListenPort = [int]$ListenPortTextBox.Text
    $wgIP = $ServerIPTextBox.Text
    $wgPORT = [int]$ServerPortTextBox.Text
    $configPath = $ConfigPathTextBox.Text

    try {
        Stop-WireGuardProcess
        Append-Log "Stopping WireGuard process..."
        Edit-WireGuardConfig -configPath $configPath -listenPort $wgListenPort
        Append-Log "WireGuard configuration updated."
        Send-UdpPacket -ipAddress $wgIP -port $wgPORT -listenPort $wgListenPort
        Append-Log "UDP packet sent."
        Start-WireGuardProcess -configPath $configPath
        Append-Log "WireGuard process started successfully."
    } catch {
        Append-Log "Error: $_"
    }
})

# Event handler for StopWireGuardButton
$StopWireGuardButton.Add_Click({
    try {
        Stop-WireGuardProcess
        Append-Log "WireGuard process stopped."
    } catch {
        Append-Log "Error stopping WireGuard process: $_"
    }
})

# Function to stop all WireGuard processes
function Stop-WireGuardProcess {
    try {
        Get-Process -Name "WireGuard" -ErrorAction SilentlyContinue | ForEach-Object {
            $_.Kill()
        }
    } catch {
        Append-Log "Error stopping WireGuard process: $_"
    }
}

# Function to edit WireGuard config
function Edit-WireGuardConfig {
    param (
        [string]$configPath,
        [int]$listenPort
    )

    $configContent = Get-Content -Path $configPath
    $interfaceSectionFound = $false

    for ($i = 0; $i -lt $configContent.Length; $i++) {
        if ($configContent[$i] -match "^\[Interface\]") {
            $interfaceSectionFound = $true
            $i++
            while ($i -lt $configContent.Length -and $configContent[$i] -notmatch "^\[Peer\]") {
                if ($configContent[$i] -match "^ListenPort\s*=") {
                    $configContent[$i] = "ListenPort = $listenPort"
                    break
                }
                $i++
            }
            if ($i -ge $configContent.Length -or $configContent[$i] -match "^\[Peer\]") {
                $configContent = $configContent[0..($i-1)] + "ListenPort = $listenPort" + $configContent[$i..($configContent.Length-1)]
            }
            break
        }
    }

    if (-not $interfaceSectionFound) {
        $configContent += "[Interface]"
        $configContent += "ListenPort = $listenPort"
    }

    $configContent | Set-Content -Path $configPath
}

# Function to send UDP packet
function Send-UdpPacket {
    param (
        [string]$ipAddress,
        [int]$port,
        [int]$listenPort
    )

    try {
        $payload = "This is a larger payload to test UDP packet sending functionality. " * 10  # Increase the payload size
        $EndPoints = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ipAddress), $port)
        $Socket = New-Object System.Net.Sockets.UDPClient $listenPort
        $SendMessage = $Socket.Send([Text.Encoding]::ASCII.GetBytes($payload), $payload.Length, $EndPoints)
        $Socket.Close()
        Append-Log "UDP packet sent successfully through port $listenPort."
    } catch {
        Append-Log "Error sending UDP packet: $_"
    }
}

# Function to start WireGuard process and log output
function Start-WireGuardProcess {
    param (
        [string]$configPath
    )

    try {
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = "C:\Program Files\WireGuard\WireGuard.exe"
        $processInfo.Arguments = "/installtunnelservice $configPath"
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        $process.Start() | Out-Null

        $output = $process.StandardOutput.ReadToEnd()
        $errorOutput = $process.StandardError.ReadToEnd()

        if ($output) {
            Append-Log "WireGuard Output: $output"
        }
        if ($errorOutput) {
            Append-Log "WireGuard Error: $errorOutput"
        }

        $process.WaitForExit()
    } catch {
        Append-Log "Error starting WireGuard process: $_"
    }
}

# Function to append log messages
function Append-Log {
    param (
        [string]$message
    )

    if ($StatusTextBlock.Text -eq "") {
        $StatusTextBlock.Text = $message
    } else {
        $StatusTextBlock.Text += "`n$message"
    }
}

# Show the form
$Form.ShowDialog() | Out-Null