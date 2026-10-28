# Monitor GoAhead web server for weak Diffie-Hellman parameters in TLS handshakes
# This script uses tshark to monitor TLS handshakes for weak Diffie-Hellman parameters (1-byte modulus) on GoAhead web servers.
# Requires: Wireshark (tshark) and BurntToast PowerShell module for notifications
# Install BurntToast module if not already installed

# Check if BurntToast module is installed, if not, install it
if (-not (Get-Module -ListAvailable -Name BurntToast)) {
    Install-Module -Name BurntToast -Force -Scope CurrentUser
}

$Interface = "Ethernet"          # change to your interface name (run `tshark -D` to list them)
$Ports     = "443 or 8443"
$LogFile   = "$env:USERPROFILE\Desktop\goahead_dh_alerts.log"
$tshark = "C:\Program Files\Wireshark\tshark.exe"

Write-Host "Monitoring for GoAhead weak DH parameters... (Ctrl+C to stop)" -ForegroundColor Cyan

& $tshark -i $Interface -f "tcp port $Ports" `
  -Y 'tls.handshake.type == 12 && frame contains 00:01:ff:00:01:02' `
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport `
  -l 2>$null | ForEach-Object {

    $line = $_
    $msg  = "Weak DH (1-byte modulus) detected:`n$line"

    # Windows toast notification
    New-BurntToastNotification -Text "GoAhead TLS Vulnerability", $msg -Sound 'Alarm'

    # Also log it
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  $line" | Tee-Object -FilePath $LogFile -Append

    # Optional: play system sound
    [System.Media.SystemSounds]::Exclamation.Play()
}