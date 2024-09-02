# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo "powershell.exe"
    $startInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File ""$PSCommandPath"""
    $startInfo.Verb = "runas" 
    [System.Diagnostics.Process]::Start($startInfo).WaitForExit()
} else {

    # Load assemblies
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName System.Windows.Forms

    # Load XAML
    [xml]$Xaml = Get-Content -Path ".\MainWindow.2.0.xaml"
    if ($null -eq $Xaml) { Write-Error "Failed to load XAML file."; return }
    $Reader = New-Object System.Xml.XmlNodeReader $Xaml
    $MainWindow = [Windows.Markup.XamlReader]::Load($Reader) 
    if ($null -eq $MainWindow) { Write-Error "Failed to create window from XAML."; return }

    # --- Control Binding --- 
    $ListenPortInput = $MainWindow.FindName("ListenPortInput")
    $ServerIPInput = $MainWindow.FindName("ServerIPInput")
    $ServerPortInput = $MainWindow.FindName("ServerPortInput")
    $ConfigPathInput = $MainWindow.FindName("ConfigPathInput")
    # $PrivateKeyInput = $MainWindow.FindName("PrivateKeyInput")
    $UseSystemProxyCheckbox = $MainWindow.FindName("UseSystemProxyCheckbox")
    $ImportConfigButton = $MainWindow.FindName("ImportConfigButton")
    $StartTunnelButton = $MainWindow.FindName("StartTunnelButton") 
    $StopTunnelButton = $MainWindow.FindName("StopTunnelButton") 
    $SendUdpButton = $MainWindow.FindName("SendUdpButton") 
    $StatusLog = $MainWindow.FindName("StatusLog")
    $TestPortRangeButton = $MainWindow.FindName("TestPortRangeButton")
    $PortRangeStartInput = $MainWindow.FindName("PortRangeStartInput")
    $PortRangeEndInput = $MainWindow.FindName("PortRangeEndInput")
    $ToggleLogButton = $MainWindow.FindName("ToggleLogButton")
    $LogScrollViewer = $MainWindow.FindName("LogScrollViewer") 
    $PortScanProgressBar = $MainWindow.FindName("PortScanProgressBar") # Bind the progress bar

    # --- Global Variables ---
    $global:udpClient = $null
    $global:wireGuardProcess = $null

    # UDP Payload 
    $payload = ":)"

    # --- Functions ---

    # Function to log messages to the StatusLog text box
    function Log-Message {
        param (
            [string]$message,
            [string]$logLevel = "INFO" 
        ) 
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $StatusLog.Text += "`n[$timestamp] [$logLevel] $message" 
    }

    # Function to stop the WireGuard process
    function Stop-WireGuardProcess {
        if ($global:wireGuardProcess -ne $null -and -not $global:wireGuardProcess.HasExited) {
            $global:wireGuardProcess.Kill()
            $global:wireGuardProcess = $null 
        }
    }

    # Function to edit the WireGuard configuration file
    function Edit-WireGuardConfig {
        param (
            [string]$configPath,
            [int]$listenPort
        )
        (Get-Content -Path $configPath) -replace '(?m)^ListenPort\s*=\s*\d+$', "ListenPort = $listenPort" | 
            Set-Content -Path $configPath 
    }

    # Function to send a UDP packet, handle retries, and prompt for listen port change
    function Send-UdpPacket {
        param (
            [string]$ipAddress,
            [int]$serverPort,       
            [int]$startingListenPort, 
            [int]$timeout = 3,       
            [int]$maxRetries = 5     
        )

        $retryCount = 0
        $currentListenPort = $startingListenPort

        while ($retryCount -le $maxRetries) {
            try {
                if ($null -eq $global:udpClient) {
                    $global:udpClient = New-Object System.Net.Sockets.UDPClient($currentListenPort)
                } else {
                    $global:udpClient.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $currentListenPort)))
                }

                $EndPoints = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ipAddress), $serverPort)
                $global:udpClient.Send([Text.Encoding]::ASCII.GetBytes($payload), $payload.Length, $EndPoints) 

                $global:udpClient.Client.ReceiveTimeout = $timeout * 1000 

                $receivedData = $global:udpClient.Receive([ref] $EndPoints)
                $message = [text.encoding]::ASCII.GetString($receivedData)
                Log-Message "Received response: '$message' from server on listen port $currentListenPort."

                # --- Prompt user to use the successful listen port ---
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "Response received on listen port $currentListenPort. Do you want to set this as your listen port and start the tunnel?", 
                    "Confirmation", 
                    [System.Windows.Forms.MessageBoxButtons]::YesNo, 
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )

                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    $ListenPortInput.Text = $currentListenPort  # Set the listen port in the input field
                    Start-Tunnel  # Call the Start-Tunnel function (define this function below)
                }

                return $true # Indicate success
            }
            catch [System.Net.Sockets.SocketException] {
                Log-Message "No response from server within timeout on listen port $currentListenPort. Retrying..." "WARNING"
                $retryCount++
                $currentListenPort++ 
            }
        }

        Log-Message "Failed to send UDP packet after $maxRetries attempts." "ERROR"
        [System.Windows.Forms.MessageBox]::Show("Failed to send UDP packet after $maxRetries attempts.", "Error", 0)
        return $false
    }

    # --- New Function: Start-Tunnel --- 
    function Start-Tunnel {
        $wgListenPort = [int]$ListenPortInput.Text
        $wgIP = $ServerIPInput.Text
        $wgPORT = [int]$ServerPortInput.Text
        $configPath = $ConfigPathInput.Text

        try {
            Stop-WireGuardProcess
            Log-Message "Stopping existing WireGuard process..." 
            Edit-WireGuardConfig -configPath $configPath -listenPort $wgListenPort
            Log-Message "WireGuard configuration updated."  
            Start-WireGuardProcess -configPath $configPath
        } catch {
            Log-Message  ("Error: {0}" -f $_.Exception.Message) -bor 3
        }
    }
    # Function to start the WireGuard process
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
            $global:wireGuardProcess = New-Object System.Diagnostics.Process
            $global:wireGuardProcess.StartInfo = $processInfo
            $global:wireGuardProcess.Start() | Out-Null

            $output = $global:wireGuardProcess.StandardOutput.ReadToEnd()
            $errorOutput = $global:wireGuardProcess.StandardError.ReadToEnd()

            if ($output) {
                Log-Message "WireGuard Output: $output" 
            }
            if ($errorOutput) {
                Log-Message  ("WireGuard Error: $errorOutput" ) -bor 3
            }

            $global:wireGuardProcess.WaitForExit()
        } catch {
            Log-Message ("Error starting WireGuard process: {0}" -f $_.Exception.Message) -bor 3
        }
    }

    # Function to process and load a WireGuard configuration file
    function Process-WireGuardConfig {
        param (
            [string]$filePath
        )

        try {
            $configContent = Get-Content -Path $filePath 

            foreach ($line in $configContent) {
                if ($line -match "^Endpoint\s*=\s*(?<ip>[\d\.]+):(?<port>\d+)") {
                    $ServerIPInput.Text = $matches['ip']
                    $ServerPortInput.Text = $matches['port']
                } elseif ($line -match "^ListenPort\s*=\s*(?<port>\d+)") {
                    $ListenPortInput.Text = $matches['port']
                } 
                # Removed code to set private key
            }

            $ConfigPathInput.Text = $filePath 
            Log-Message "Configuration loaded from file: $filePath"
        } catch {
            Log-Message  ("Error loading configuration: {0}" -f $_.Exception.Message) -bor 3
            [System.Windows.Forms.MessageBox]::Show("Error loading configuration file.", "Error", 0)
        }
    }

    function Test-UdpPortRange {
        param (
            [string]$ipAddress,
            [int]$serverPort,
            [int]$startPort,
            [int]$endPort,
            [int]$timeout = 2
        )

        $successfulPorts = @()
        $totalPorts = $endPort - $startPort + 1 # Number of ports to scan

        # Initialize progress bar
        $PortScanProgressBar.Minimum = 0
        $PortScanProgressBar.Maximum = $totalPorts
        $PortScanProgressBar.Value = 0

        for ($port = $startPort; $port -le $endPort; $port++) {
            # Update progress bar
            $PortScanProgressBar.Value++

            try {
                $udpClient = New-Object System.Net.Sockets.UdpClient($port) 
                $EndPoints = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ipAddress), $serverPort)
                $udpClient.Send([Text.Encoding]::ASCII.GetBytes($payload), $payload.Length, $EndPoints)

                $udpClient.Client.ReceiveTimeout = $timeout * 1000
                $receivedData = $udpClient.Receive([ref] $EndPoints) 
                $message = [text.encoding]::ASCII.GetString($receivedData)
                Log-Message "Response received on port $port`: `'$message`'"
                $successfulPorts += $port # Add the correct port to the array 

                # Stop scanning if we have a successful port
                break 
            }
            catch [System.Net.Sockets.SocketException] {
                Log-Message "No response on port $port within timeout." "WARNING" 
            } 
            finally {
                if ($udpClient) { $udpClient.Close() } 
            }
        }

        return $successfulPorts
    }

    function Set-RecommendedPort {
        $targetIP = $ServerIPInput.Text
        $targetPort = [int]$ServerPortInput.Text
        $startPort = [int]$PortRangeStartInput.Text
        $endPort = [int]$PortRangeEndInput.Text

        $successfulPorts = Test-UdpPortRange -ipAddress $targetIP -serverPort $targetPort -startPort $startPort -endPort $endPort

        if ($successfulPorts.Count -gt 0) {
            $selectedPort = $successfulPorts[0] # Take the first successful port
            $ListenPortInput.Text = $selectedPort
            Log-Message "Listen port set to: $selectedPort"
        } else {
            # Display a message if no valid port was found in the range
            [System.Windows.Forms.MessageBox]::Show("No responses received within the specified port range. Please check your server settings and try again.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) 
            # Start the "Test Ports" logic
            $TestPortRangeButton.PerformClick() 
        }
    }

    # --- Event Handlers ---

    # Event handler for the "Use System Proxy" checkbox
    $UseSystemProxyCheckbox.Add_Click({
        $useSystemProxy = $UseSystemProxyCheckbox.IsChecked
        if ($useSystemProxy) {
            Log-Message  "Enabling system proxy..."
            try { netsh winhttp import proxy source=ie } 
            catch { Log-Message  ("Error enabling system proxy: {0}" -f $_.Exception.Message) -bor 3 }
        } else {
            Log-Message  "Disabling system proxy..."
            try { netsh winhttp reset proxy } 
            catch { Log-Message  ("Error disabling system proxy: {0}" -f $_.Exception.Message) -bor 3 }
        }
    })

    # Event handler for the "Import Config" button
    $ImportConfigButton.Add_Click({
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Filter = "WireGuard Config Files (*.conf)|*.conf"
        if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $configPath = $openFileDialog.FileName
            Process-WireGuardConfig -filePath $configPath 

            # Set default port range based on the imported listen port
            $listenPort = [int]$ListenPortInput.Text
            $PortRangeStartInput.Text = ($listenPort - 10).ToString()
            $PortRangeEndInput.Text = ($listenPort + 10).ToString()
        } 
    })

    # Event handler for the "Start Tunnel" button
    $StartTunnelButton.Add_Click({
        $wgListenPort = [int]$ListenPortInput.Text
        $wgIP = $ServerIPInput.Text
        $wgPORT = [int]$ServerPortInput.Text
        $configPath = $ConfigPathInput.Text

        try {
            Stop-WireGuardProcess
            Log-Message "Stopping existing WireGuard process..." 
            Edit-WireGuardConfig -configPath $configPath -listenPort $wgListenPort
            Log-Message "WireGuard configuration updated."  
            Start-WireGuardProcess -configPath $configPath
        } catch {
            Log-Message  ("Error: {0}" -f $_.Exception.Message) -bor 3
        }
    })

    $StopTunnelButton.Add_Click({
        try {
            Stop-WireGuardProcess
            Log-Message "WireGuard tunnel stopped."
        } catch {
            Log-Message ("Error stopping WireGuard tunnel: {0}" -f $_.Exception.Message) -bor 3
        }
    })

    # Event handler for the "Test Port Range" button
    $TestPortRangeButton.Add_Click({
        # Validate form fields 
        if ($ServerIPInput.Text -eq "" -or $ServerPortInput.Text -eq "" -or $PortRangeStartInput.Text -eq "" -or $PortRangeEndInput.Text -eq "") {
            [System.Windows.Forms.MessageBox]::Show("Please fill in all the required fields.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }

        $targetIP = $ServerIPInput.Text
        $targetPort = [int]$ServerPortInput.Text
        $startPort = [int]$PortRangeStartInput.Text
        $endPort = [int]$PortRangeEndInput.Text

        $successfulPorts = Test-UdpPortRange -ipAddress $targetIP -serverPort $targetPort -startPort $startPort -endPort $endPort

        if ($successfulPorts.Count -gt 0) {
            # ---  Make sure the selected port is within the range ---
            $selectedPort = $successfulPorts | Where-Object { $_ -ge $startPort -and $_ -le $endPort } | Select-Object -First 1

            if ($selectedPort) {
                $ListenPortInput.Text = $selectedPort
                Log-Message "Listen port set to: $selectedPort"
                [System.Windows.Forms.MessageBox]::Show("Listen port set to: $selectedPort. Ready to start tunnel.", "Information", 0) 
            } else {
                # Display a message if no valid port was found in the range
                [System.Windows.Forms.MessageBox]::Show("No responses received within the specified port range.", "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) 
            }
        } 
    })

        # Event handler for the "Minimize Log" button
        $ToggleLogButton.Add_Click({
            if ($LogScrollViewer.Height -gt 0) {
                $LogScrollViewer.Height = 0  # Minimize the log area
                $ToggleLogButton.Content = "Maximize Log"
            } else {
                $LogScrollViewer.Height = [Double]::NaN # Restore auto height 
                $ToggleLogButton.Content = "Minimize Log"
            }
        })

        # Disable "Test Ports" button if the form is empty
        $TestPortRangeButton.IsEnabled = $false
        $ListenPortInput.Add_TextChanged({
            $TestPortRangeButton.IsEnabled = $ListenPortInput.Text -ne "" -and $ServerIPInput.Text -ne "" -and $ServerPortInput.Text -ne "" -and $PortRangeStartInput.Text -ne "" -and $PortRangeEndInput.Text -ne ""
        })
        $ServerIPInput.Add_TextChanged({
            $TestPortRangeButton.IsEnabled = $ListenPortInput.Text -ne "" -and $ServerIPInput.Text -ne "" -and $ServerPortInput.Text -ne "" -and $PortRangeStartInput.Text -ne "" -and $PortRangeEndInput.Text -ne ""
        })
        $ServerPortInput.Add_TextChanged({
            $TestPortRangeButton.IsEnabled = $ListenPortInput.Text -ne "" -and $ServerIPInput.Text -ne "" -and $ServerPortInput.Text -ne "" -and $PortRangeStartInput.Text -ne "" -and $PortRangeEndInput.Text -ne ""
        })
        $PortRangeStartInput.Add_TextChanged({
            $TestPortRangeButton.IsEnabled = $ListenPortInput.Text -ne "" -and $ServerIPInput.Text -ne "" -and $ServerPortInput.Text -ne "" -and $PortRangeStartInput.Text -ne "" -and $PortRangeEndInput.Text -ne ""
        })
        $PortRangeEndInput.Add_TextChanged({
            $TestPortRangeButton.IsEnabled = $ListenPortInput.Text -ne "" -and $ServerIPInput.Text -ne "" -and $ServerPortInput.Text -ne "" -and $PortRangeStartInput.Text -ne "" -and $PortRangeEndInput.Text -ne ""
        })
    


    # Event handler to close the UDP client when the window closes
    $MainWindow.Add_Closing({
        if ($global:udpClient -ne $null) { $global:udpClient.Close() }
    })

    # Show the main window
    $MainWindow.ShowDialog() | Out-Null
} 
