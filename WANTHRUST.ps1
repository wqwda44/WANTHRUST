# WANTHRUST_Powershell_Final.ps1
# Run: powershell -ExecutionPolicy Bypass -File WANTHRUST_Powershell_Final.ps1
# GitHub: https://github.com/wqwda44
# Telegram: https://t.me/chanel441

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ================= GLOBAL =================

$Version = "2.2"
$Author  = "44"
$RepoURL = "https://github.com/wqwda44"
$TGURL   = "https://t.me/chanel441"

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ================= COLORS =================

$Colors = @{
    Red     = "Red"
    Green   = "Green"
    Yellow  = "Yellow"
    Cyan    = "Cyan"
    Magenta = "Magenta"
    White   = "White"
    Gray    = "Gray"
}

function Write-Color {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Show-Banner {
    Clear-Host
    Write-Color "==============================================================" $Colors.Green
    Write-Color "   WANTHRUST PRO v$Version - WiFi Toolkit" $Colors.Green
    Write-Color "   Author: 44" $Colors.Red
    Write-Color "   Telegram: $TGURL" $Colors.Yellow
    Write-Color "   GitHub:   $RepoURL" $Colors.Yellow
    Write-Color "   Windows PowerShell Edition" $Colors.Cyan
    Write-Color "==============================================================" $Colors.Green
    Write-Host ""
    Write-Color "[*] Admin: $(if($IsAdmin){'YES'}else{'NO (limited)'})" $Colors.Cyan
    Write-Color "[*] OS: $((Get-WmiObject Win32_OperatingSystem).Caption)" $Colors.Cyan
    Write-Color "[*] User: $env:USERNAME" $Colors.Cyan
    Write-Color "[*] Time: $(Get-Date -Format 'HH:mm:ss')" $Colors.Cyan
    Write-Host ""
}


function Show-Menu {
    Show-Banner
    Write-Color "[MAIN MENU]" $Colors.Magenta
    Write-Host ""
    
    $menuItems = @(
        @{Id=1; Title="Scan WiFi networks (full analysis)"},
        @{Id=2; Title="Extract saved WiFi passwords"},
        @{Id=3; Title="Export all WiFi profiles (XML)"},
        @{Id=4; Title="Create hotspot/Access Point"},
        @{Id=5; Title="Attack weak networks (WEP/Open)"},
        @{Id=6; Title="Traffic analysis (requires WinPcap)"},
        @{Id=7; Title="Auto data collection"},
        @{Id=8; Title="Network security audit"},
        @{Id=9; Title="Settings and utilities"},
        @{Id=0; Title="Exit"}
    )
    
    foreach ($item in $menuItems) {
        Write-Color "  [$($item.Id)] $($item.Title)" $Colors.Yellow
    }
    Write-Host ""
}

function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

# ========== ОСНОВНЫЕ ФУНКЦИИ ==========

function Scan-WiFiNetworks {
    Write-Color "`n[+] Scanning WiFi networks..." $Colors.Green
    
    try {
        Write-Color "[~] Running netsh wlan..." $Colors.Cyan
        $scanResult = netsh wlan show networks mode=bssid
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $scanFile = "WiFi_Scan_$timestamp.txt"
        $scanResult | Out-File -FilePath $scanFile -Encoding UTF8
        
        $networks = @()
        $currentNet = @{}
        
        foreach ($line in $scanResult -split "`r`n") {
            $line = $line.Trim()
            
            if ($line -match "^SSID \d+ : (.+)$") {
                if ($currentNet.Count -gt 0) {
                    $networks += [PSCustomObject]$currentNet
                }
                $currentNet = @{SSID = $matches[1]}
            }
            elseif ($line -match "BSSID \d+ : (.+)") { $currentNet.BSSID = $matches[1] }
            elseif ($line -match "Signal.*: (\d+)%") { $currentNet.Signal = $matches[1] + "%" }
            elseif ($line -match "Channel.*: (\d+)") { $currentNet.Channel = $matches[1] }
            elseif ($line -match "Authentication.*: (.+)") { $currentNet.Auth = $matches[1] }
            elseif ($line -match "Encryption.*: (.+)") { $currentNet.Encryption = $matches[1] }
        }
        
        if ($currentNet.Count -gt 0) {
            $networks += [PSCustomObject]$currentNet
        }
        
        if ($networks.Count -gt 0) {
            $networks | Format-Table -Property SSID, Signal, Channel, Auth, Encryption -AutoSize
            
            $networks | Export-Csv -Path "WiFi_Networks_$timestamp.csv" -NoTypeInformation -Encoding UTF8
            
            Write-Color "`n[+] Networks found: $($networks.Count)" $Colors.Green
            Write-Color "[+] Results saved to:" $Colors.Green
            Write-Color "    - $scanFile" $Colors.Cyan
            Write-Color "    - WiFi_Networks_$timestamp.csv" $Colors.Cyan
            
            $vulnerable = $networks | Where-Object {
                $_.Auth -match "WEP|Open" -or 
                $_.Encryption -match "WEP|None"
            }
            
            if ($vulnerable.Count -gt 0) {
                Write-Color "`n[!] VULNERABLE NETWORKS FOUND:" $Colors.Red
                $vulnerable | Format-Table -AutoSize
                $vulnerable | Export-Csv -Path "Vulnerable_Networks_$timestamp.csv" -NoTypeInformation
            }
        } else {
            Write-Color "[-] No networks found" $Colors.Red
        }
        
    } catch {
        Write-Color "[-] Scan error: $_" $Colors.Red
    }
    
    Read-Host "`nPress Enter to continue"
}

function Get-WiFiPasswords {
    Write-Color "`n[+] Extracting saved WiFi passwords..." $Colors.Green
    
    try {
        $profilesOutput = netsh wlan show profiles
        $profiles = @()
        
        foreach ($line in $profilesOutput -split "`r`n") {
            if ($line -match "All User Profile.*: (.+)") {
                $profiles += $matches[1].Trim()
            }
        }
        
        Write-Color "[~] Profiles found: $($profiles.Count)" $Colors.Cyan
        
        $passwords = @()
        $counter = 0
        
        foreach ($profile in $profiles) {
            $counter++
            Write-Progress -Activity "Extracting passwords" -Status "Processing: $profile" -PercentComplete (($counter / $profiles.Count) * 100)
            
            try {
                $profileInfo = netsh wlan show profile name="$profile" key=clear
                
                $password = $null
                foreach ($line in $profileInfo -split "`r`n") {
                    if ($line -match "Key Content|Key Material.*: (.+)") {
                        $password = $matches[1].Trim()
                        break
                    }
                }
                
                if ($password) {
                    $passwords += [PSCustomObject]@{
                        SSID = $profile
                        Password = $password
                        Security = "WPA2"
                        DateAdded = (Get-Date).ToString("yyyy-MM-dd")
                    }
                }
            } catch {
                Write-Color "[~] Error with profile $profile : $_" $Colors.Yellow
            }
        }
        
        Write-Progress -Activity "Extracting passwords" -Completed
        
        if ($passwords.Count -gt 0) {
            $passwords | Format-Table -Property SSID, Password -AutoSize
            
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $passwords | Export-Csv -Path "WiFi_Passwords_$timestamp.csv" -NoTypeInformation -Encoding UTF8
            $passwords | ForEach-Object { "SSID: $($_.SSID)`nPassword: $($_.Password)`n" } | Out-File "WiFi_Passwords_$timestamp.txt" -Encoding UTF8
            $passwords | ConvertTo-Json | Out-File "WiFi_Passwords_$timestamp.json" -Encoding UTF8
            
            Write-Color "`n[+] Passwords extracted: $($passwords.Count)" $Colors.Green
            Write-Color "[+] Results saved in formats:" $Colors.Green
            Write-Color "    - WiFi_Passwords_$timestamp.csv" $Colors.Cyan
            Write-Color "    - WiFi_Passwords_$timestamp.txt" $Colors.Cyan
            Write-Color "    - WiFi_Passwords_$timestamp.json" $Colors.Cyan
            
        } else {
            Write-Color "[-] No passwords found" $Colors.Red
        }
        
    } catch {
        Write-Color "[-] Critical error: $_" $Colors.Red
    }
    
    Read-Host "`nPress Enter to continue"
}

function Export-WiFiProfiles {
    Write-Color "`n[+] Exporting WiFi profiles..." $Colors.Green
    
    if (-not $IsAdmin) {
        Write-Color "[-] Admin rights required" $Colors.Red
        Read-Host "`nPress Enter to continue"
        return
    }
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $exportDir = "WiFi_Profiles_$timestamp"
        
        New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
        
        Write-Color "[~] Exporting profiles with keys..." $Colors.Cyan
        $exportResult = netsh wlan export profile folder="$exportDir" key=clear
        
        $exportedFiles = Get-ChildItem -Path $exportDir -Filter "*.xml"
        
        if ($exportedFiles.Count -gt 0) {
            Write-Color "[+] Profiles exported: $($exportedFiles.Count)" $Colors.Green
            
            $readmeContent = @"
# WiFi Profiles Export
Exported on: $(Get-Date)
Total profiles: $($exportedFiles.Count)

## How to import:
1. Run CMD as Administrator
2. netsh wlan add profile filename="ProfileName.xml"

## Security Note:
- XML files contain passwords in clear text
- Store securely and delete after use

## Files:
$($exportedFiles | ForEach-Object { "- $($_.Name)" } | Out-String)
"@
            
            $readmeContent | Out-File -FilePath "$exportDir/README.md" -Encoding UTF8
            
            if (Test-Command "Compress-Archive") {
                Compress-Archive -Path "$exportDir/*" -DestinationPath "WiFi_Profiles_$timestamp.zip" -Force
                Write-Color "[+] Archive created: WiFi_Profiles_$timestamp.zip" $Colors.Green
            }
            
            Write-Color "[+] All files saved in: $exportDir" $Colors.Green
            Write-Color "[+] To import on another PC:" $Colors.Yellow
            Write-Color "    netsh wlan add profile filename=`"filename.xml`"" $Colors.White
            
        } else {
            Write-Color "[-] No files exported" $Colors.Red
        }
        
    } catch {
        Write-Color "[-] Export error: $_" $Colors.Red
    }
    
    Read-Host "`nPress Enter to continue"
}

function Create-Hotspot {
    Write-Color "`n[+] Creating hotspot..." $Colors.Green
    
    if (-not $IsAdmin) {
        Write-Color "[-] Admin rights required" $Colors.Red
        Read-Host "`nPress Enter to continue"
        return
    }
    
    try {
        $drivers = netsh wlan show drivers
        if ($drivers -notmatch "Hosted network supported.*: Yes") {
            Write-Color "[-] Adapter doesn't support hosted network" $Colors.Red
            Read-Host "`nPress Enter to continue"
            return
        }
        
        Write-Color "[+] Hosted network supported" $Colors.Green
        
        Write-Color "`n[?] Choose hotspot type:" $Colors.Yellow
        Write-Color "  1. Regular hotspot (for internet)" $Colors.White
        Write-Color "  2. Phishing hotspot (clone existing network)" $Colors.White
        Write-Color "  3. Open hotspot (no password)" $Colors.White
        Write-Color "  4. Back" $Colors.White
        
        $typeChoice = Read-Host "`nChoice"
        
        if ($typeChoice -eq "4") { return }
        
        if ($typeChoice -eq "2") {
            Write-Color "`n[~] Scanning networks for cloning..." $Colors.Cyan
            $networks = netsh wlan show networks | Select-String "SSID" | ForEach-Object {
                if ($_ -match "SSID \d+ : (.+)") { $matches[1] }
            }
            
            if ($networks.Count -eq 0) {
                Write-Color "[-] No networks found" $Colors.Red
                return
            }
            
            Write-Color "`n[+] Available networks:" $Colors.Green
            for ($i = 0; $i -lt $networks.Count; $i++) {
                Write-Color "  $($i+1). $($networks[$i])" $Colors.White
            }
            
            $networkChoice = Read-Host "`nSelect network to clone (number)"
            if ($networkChoice -match "^\d+$" -and [int]$networkChoice -le $networks.Count) {
                $ssid = $networks[[int]$networkChoice - 1]
                Write-Color "[~] Cloning network: $ssid" $Colors.Yellow
            } else {
                $ssid = Read-Host "Network name (SSID)"
            }
        } else {
            $ssid = Read-Host "Network name (SSID)"
        }
        
        $password = ""
        if ($typeChoice -ne "3") {
            $password = Read-Host "Password (min 8 chars)"
            while ($password.Length -lt 8) {
                Write-Color "[-] Password too short (min 8 chars)" $Colors.Red
                $password = Read-Host "Password (min 8 chars)"
            }
        }
        
        $authEncryption = if ($typeChoice -eq "3") {
            @"
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <protected>false</protected>
            </sharedKey>
"@
        } else {
            @"
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$password</keyMaterial>
            </sharedKey>
"@
        }
        
        $profileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$ssid</name>
    <SSIDConfig>
        <SSID>
            <name>$ssid</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            $authEncryption
        </security>
    </MSM>
</WLANProfile>
"@
        
        $profileFile = "$ssid.xml"
        $profileXml | Out-File -FilePath $profileFile -Encoding UTF8
        
        Write-Color "`n[+] Profile created: $profileFile" $Colors.Green
        
        Write-Color "`n[!] SETUP INSTRUCTIONS:" $Colors.Yellow
        Write-Color "1. Add profile:" $Colors.White
        Write-Color "   netsh wlan add profile filename=`"$profileFile`"" $Colors.Cyan
        
        Write-Color "2. Configure hosted network:" $Colors.White
        Write-Color "   netsh wlan set hostednetwork mode=allow ssid=`"$ssid`" key=`"$password`" keyUsage=persistent" $Colors.Cyan
        
        Write-Color "3. Start hosted network:" $Colors.White
        Write-Color "   netsh wlan start hostednetwork" $Colors.Cyan
        
        Write-Color "4. Share internet connection:" $Colors.White
        Write-Color "   (in network connections settings)" $Colors.Cyan
        
        Write-Color "`n[!] TO STOP:" $Colors.Yellow
        Write-Color "   netsh wlan stop hostednetwork" $Colors.Red
        
        if ($typeChoice -eq "2") {
            Write-Color "`n[!] PHISHING TIPS:" $Colors.Red
            Write-Color "• Disable original $ssid network" $Colors.White
            Write-Color "• Use stronger signal" $Colors.White
            Write-Color "• Setup phishing page" $Colors.White
        }
        
    } catch {
        Write-Color "[-] Error: $_" $Colors.Red
    }
    
    Read-Host "`nPress Enter to continue"
}

function Attack-WeakNetworks {
    Write-Color "`n[+] Attacking weak networks..." $Colors.Green
    Write-Color "[!] Requires special hardware" $Colors.Red
    
    Write-Color "`n[?] Choose attack type:" $Colors.Yellow
    Write-Color "  1. Detect WEP networks" $Colors.White
    Write-Color "  2. Attack open networks" $Colors.White
    Write-Color "  3. Deauth attack (needs monitor mode)" $Colors.White
    Write-Color "  4. Dictionary attack on captured hashes" $Colors.White
    Write-Color "  5. Back" $Colors.White
    
    $attackChoice = Read-Host "`nChoice"
    
    if ($attackChoice -eq "5") { return }
    
    switch ($attackChoice) {
        "1" {
            Write-Color "`n[+] Searching for WEP networks..." $Colors.Green
            Write-Color "[~] Run airodump-ng (requires Linux/special adapter)" $Colors.Yellow
            Write-Color "[!] For Windows use:" $Colors.White
            Write-Color "• CommView for WiFi" $Colors.Cyan
            Write-Color "• Acrylic WiFi Professional" $Colors.Cyan
            Write-Color "• Aircrack-ng on Linux" $Colors.Cyan
        }
        "2" {
            Write-Color "`n[+] Attacking open networks..." $Colors.Green
            Write-Color "[~] 1. Connect to open network" $Colors.White
            Write-Color "[~] 2. Analyze traffic (Wireshark)" $Colors.White
            Write-Color "[~] 3. Capture sessions" $Colors.White
            Write-Color "[!] Use proxy (Burp Suite, MITMproxy)" $Colors.Yellow
        }
        "3" {
            Write-Color "`n[+] Deauth attack..." $Colors.Green
            Write-Color "[~] Sending deauth packets to disconnect clients" $Colors.White
            Write-Color "[!] Requires:" $Colors.Red
            Write-Color "• Monitor mode capable adapter" $Colors.White
            Write-Color "• aireplay-ng (Linux)" $Colors.White
            Write-Color "• Packet injection drivers" $Colors.White
        }
        "4" {
            Write-Color "`n[+] Dictionary attack..." $Colors.Green
            Write-Color "[~] Using hashcat to crack handshake" $Colors.White
            
            if (Test-Command "hashcat") {
                Write-Color "[+] Hashcat detected" $Colors.Green
                Write-Color "[~] Example command:" $Colors.Cyan
                Write-Color "   hashcat -m 22000 handshake.hccapx rockyou.txt" $Colors.White
            } else {
                Write-Color "[-] Hashcat not installed" $Colors.Red
                Write-Color "[~] Download: https://hashcat.net/hashcat/" $Colors.Yellow
            }
        }
    }
    
    Read-Host "`nPress Enter to continue"
}

function Analyze-Traffic {
    Write-Color "`n[+] Network traffic analysis..." $Colors.Green
    
    $tools = @{
        "Wireshark" = Test-Command "tshark"
        "Nmap" = Test-Command "nmap"
        "TCPDump" = Test-Command "tcpdump"
    }
    
    Write-Color "[~] Available tools:" $Colors.Cyan
    foreach ($tool in $tools.GetEnumerator()) {
        Write-Color "  $($tool.Key): $(if($tool.Value) {'YES'} else {'NO'})" $Colors.White
    }
    
    if ($tools.Wireshark) {
        Write-Color "`n[?] Choose action:" $Colors.Yellow
        Write-Color "  1. Capture traffic (tshark)" $Colors.White
        Write-Color "  2. Network scan (nmap)" $Colors.White
        Write-Color "  3. DNS analysis" $Colors.White
        Write-Color "  4. Find credentials in traffic" $Colors.White
        Write-Color "  5. Back" $Colors.White
        
        $analysisChoice = Read-Host "`nChoice"
        
        if ($analysisChoice -eq "5") { return }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        switch ($analysisChoice) {
            "1" {
                $interface = Read-Host "Interface name (Enter for auto)"
                if (-not $interface) {
                    $interface = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1).Name
                }
                
                $duration = Read-Host "Capture duration in seconds (30)"
                if (-not $duration) { $duration = 30 }
                
                Write-Color "[~] Capturing on interface: $interface" $Colors.Cyan
                tshark -i $interface -a duration:$duration -w "capture_$timestamp.pcap"
                Write-Color "[+] Capture saved: capture_$timestamp.pcap" $Colors.Green
            }
            "2" {
                $target = Read-Host "Target network (e.g., 192.168.1.0/24)"
                Write-Color "[~] Scanning: $target" $Colors.Cyan
                nmap -sn $target -oN "scan_$timestamp.txt"
                Write-Color "[+] Results: scan_$timestamp.txt" $Colors.Green
            }
        }
    } else {
        Write-Color "`n[-] Wireshark/tshark not installed" $Colors.Red
        Write-Color "[~] Install Wireshark: https://www.wireshark.org/" $Colors.Yellow
    }
    
    Read-Host "`nPress Enter to continue"
}

function Auto-Collect {
    Write-Color "`n[+] Auto data collection..." $Colors.Green
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $collectionDir = "Collection_$timestamp"
    
    New-Item -ItemType Directory -Path $collectionDir -Force | Out-Null
    
    Write-Color "[~] Collecting system info..." $Colors.Cyan
    systeminfo | Out-File "$collectionDir/systeminfo.txt"
    
    Write-Color "[~] Collecting network info..." $Colors.Cyan
    ipconfig /all | Out-File "$collectionDir/ipconfig.txt"
    netstat -ano | Out-File "$collectionDir/netstat.txt"
    arp -a | Out-File "$collectionDir/arp.txt"
    
    Write-Color "[~] Collecting WiFi info..." $Colors.Cyan
    netsh wlan show all | Out-File "$collectionDir/wifi_all.txt"
    netsh wlan show networks mode=bssid | Out-File "$collectionDir/wifi_networks.txt"
    netsh wlan show profiles | Out-File "$collectionDir/wifi_profiles.txt"
    
    Write-Color "[~] Exporting WiFi profiles..." $Colors.Cyan
    netsh wlan export profile folder="$collectionDir" key=clear
    
    Write-Color "[~] Collecting driver info..." $Colors.Cyan
    driverquery | Out-File "$collectionDir/drivers.txt"
    
    $report = @"
# WANTHRUST Collection Report
Collection Time: $(Get-Date)
System: $((Get-WmiObject Win32_OperatingSystem).Caption)
User: $env:USERNAME
Computer: $env:COMPUTERNAME

## Files Collected:
$(Get-ChildItem $collectionDir | ForEach-Object { "- $($_.Name)" } | Out-String)

## Security Recommendations:
1. Review exported WiFi profiles for clear-text passwords
2. Check for open networks in wifi_networks.txt
3. Monitor network connections in netstat.txt
4. Update outdated drivers from drivers.txt

## Disclaimer:
For security auditing only. Keep this information secure.
"@
    
    $report | Out-File "$collectionDir/REPORT.md" -Encoding UTF8
    
    if (Test-Command "Compress-Archive") {
        Compress-Archive -Path "$collectionDir/*" -DestinationPath "Collection_$timestamp.zip" -Force
        Remove-Item -Path $collectionDir -Recurse -Force
        Write-Color "[+] Archive created: Collection_$timestamp.zip" $Colors.Green
    } else {
        Write-Color "[+] Data saved in: $collectionDir" $Colors.Green
    }
    
    Write-Color "[+] Collection completed" $Colors.Green
    
    Read-Host "`nPress Enter to continue"
}

function Network-Security {
    Write-Color "`n[+] Network security audit..." $Colors.Green
    
    Write-Color "`n[?] Choose action:" $Colors.Yellow
    Write-Color "  1. Check WiFi vulnerabilities" $Colors.White
    Write-Color "  2. Security recommendations" $Colors.White
    Write-Color "  3. Monitor connected devices" $Colors.White
    Write-Color "  4. Secure password generator" $Colors.White
    Write-Color "  5. Back" $Colors.White
    
    $securityChoice = Read-Host "`nChoice"
    
    if ($securityChoice -eq "5") { return }
    
    switch ($securityChoice) {
        "1" {
            Write-Color "`n[+] Checking WiFi vulnerabilities..." $Colors.Green
            
            Write-Color "[~] Checking WPS..." $Colors.Cyan
            Write-Color "[!] WPS is vulnerable to brute-force" $Colors.Red
            
            $currentNetworks = netsh wlan show networks | Select-String "SSID", "Authentication", "Encryption"
            Write-Color "`n[+] Current networks:" $Colors.Green
            $currentNetworks | ForEach-Object { Write-Color "  $_" $Colors.White }
            
            Write-Color "`n[!] RECOMMENDATIONS:" $Colors.Yellow
            Write-Color "• Use WPA3 or WPA2-AES" $Colors.Green
            Write-Color "• Disable WPS in router settings" $Colors.Green
            Write-Color "• Use complex passwords (12+ chars)" $Colors.Green
            Write-Color "• Update router firmware regularly" $Colors.Green
        }
        "2" {
            Write-Color "`n[+] WiFi security recommendations:" $Colors.Green
            
            $recommendations = @"
1. ENCRYPTION:
   - Use WPA3 (most secure)
   - If no WPA3, use WPA2-AES
   - NEVER use WEP or open networks

2. ROUTER SETTINGS:
   - Change router admin password
   - Disable WPS (Wi-Fi Protected Setup)
   - Disable remote management
   - Enable MAC address filtering
   - Hide SSID (not primary protection)

3. PASSWORDS:
   - Minimum 12 characters
   - Mix uppercase, lowercase, numbers, symbols
   - Don't use personal information
   - Change every 6 months

4. ADDITIONAL:
   - Update firmware regularly
   - Use guest network for visitors
   - Enable firewall
   - Monitor connected devices
   - Use VPN for important connections

5. WHAT TO AVOID:
   - Public WiFi without VPN
   - Same passwords for different networks
   - Simple passwords (12345678, password, etc.)
   - Storing passwords unencrypted
"@
            
            Write-Color $recommendations $Colors.Cyan
            
            $recommendations | Out-File "WiFi_Security_Recommendations.txt" -Encoding UTF8
            Write-Color "`n[+] Recommendations saved to file" $Colors.Green
        }
        "4" {
            Write-Color "`n[+] Secure password generator..." $Colors.Green
            
            $length = Read-Host "Password length (12-64)"
            if (-not $length -or $length -lt 12) { $length = 16 }
            
            $count = Read-Host "Number of passwords (1-20)"
            if (-not $count -or $count -lt 1) { $count = 5 }
            
            Write-Color "`n[+] Generated passwords:" $Colors.Green
            
            $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
            $passwords = @()
            
            for ($i = 1; $i -le $count; $i++) {
                $password = ""
                for ($j = 1; $j -le $length; $j++) {
                    $password += $chars[(Get-Random -Maximum $chars.Length)]
                }
                $passwords += $password
                Write-Color "  $i. $password" $Colors.Cyan
            }
            
            $passwords | ForEach-Object { $_ } | Out-File "generated_passwords.txt" -Encoding UTF8
            Write-Color "`n[+] Passwords saved to generated_passwords.txt" $Colors.Green
        }
    }
    
    Read-Host "`nPress Enter to continue"
}

function Show-Settings {
    Write-Color "`n[+] Settings and utilities..." $Colors.Green
    
    while ($true) {
        Write-Color "`n[?] Choose option:" $Colors.Yellow
        Write-Color "  1. Check for updates" $Colors.White
        Write-Color "  2. Install dependencies" $Colors.White
        Write-Color "  3. Clean temporary files" $Colors.White
        Write-Color "  4. System information" $Colors.White
        Write-Color "  5. Test WiFi adapter" $Colors.White
        Write-Color "  6. Export logs" $Colors.White
        Write-Color "  7. Output settings" $Colors.White
        Write-Color "  8. Help and documentation" $Colors.White
        Write-Color "  9. Back to main menu" $Colors.White
        
        $settingsChoice = Read-Host "`nChoice"
        
        switch ($settingsChoice) {
            "1" {
                Write-Color "`n[+] Checking for updates..." $Colors.Green
                Write-Color "[~] GitHub: $RepoURL" $Colors.Cyan
                Write-Color "[~] Current version: v$Version" $Colors.White
                Write-Color "[!] Check repository for updates" $Colors.Yellow
            }
            "2" {
                Write-Color "`n[+] Installing dependencies..." $Colors.Green
                Write-Color "[~] Recommended tools:" $Colors.Cyan
                Write-Color "• Wireshark (traffic analysis)" $Colors.White
                Write-Color "• Nmap (network scanning)" $Colors.White
                Write-Color "• Hashcat (hash cracking)" $Colors.White
                Write-Color "• Python 3 (additional scripts)" $Colors.White
                
                $installChoice = Read-Host "`nInstall via winget? (y/n)"
                if ($installChoice -eq "y") {
                    winget install WiresharkFoundation.Wireshark
                    winget install nmap.nmap
                }
            }
            "3" {
                Write-Color "`n[+] Cleaning temporary files..." $Colors.Green
                $files = Get-ChildItem -Filter "*.txt" -File
                $files += Get-ChildItem -Filter "*.csv" -File
                $files += Get-ChildItem -Filter "*.xml" -File
                $files += Get-ChildItem -Filter "*.pcap" -File
                $files += Get-ChildItem -Filter "*.zip" -File
                $files += Get-ChildItem -Filter "WiFi_*" -Directory
                
                if ($files.Count -gt 0) {
                    $files | Remove-Item -Force -Recurse
                    Write-Color "[+] Files deleted: $($files.Count)" $Colors.Green
                } else {
                    Write-Color "[-] No files to delete" $Colors.Yellow
                }
            }
            "8" {
                Write-Color "`n[+] Help and documentation" $Colors.Green
                Write-Color "[~] GitHub repository: $RepoURL" $Colors.Cyan
                Write-Color "[~] Main commands:" $Colors.White
                Write-Color "• netsh wlan show profiles" $Colors.Cyan
                Write-Color "• netsh wlan show networks mode=bssid" $Colors.Cyan
                Write-Color "• netsh wlan export profile" $Colors.Cyan
                Write-Color "• netsh wlan set hostednetwork" $Colors.Cyan
                
                Write-Color "`n[!] LEGAL DISCLAIMER:" $Colors.Red
                Write-Color "Use only on your own networks or with permission." $Colors.White
                Write-Color "Unauthorized access to others' networks is prohibited." $Colors.White
            }
            "9" { return }
        }
        
        Read-Host "`nPress Enter to continue"
    }
}

# ========== MAIN LOOP ==========

try {
    while ($true) {
        Show-Menu
        $choice = Read-Host "`nChoose option"
        
        switch ($choice) {
            "1" { Scan-WiFiNetworks }
            "2" { Get-WiFiPasswords }
            "3" { Export-WiFiProfiles }
            "4" { Create-Hotspot }
            "5" { Attack-WeakNetworks }
            "6" { Analyze-Traffic }
            "7" { Auto-Collect }
            "8" { Network-Security }
            "9" { Show-Settings }
            "0" {
                Write-Color "`n[+] Exiting..." $Colors.Green
                Write-Color "[+] 44 " $Colors.Yellow
                Write-Color "[+] $RepoURL" $Colors.Cyan
                exit 0
            }
            default {
                Write-Color "[-] Invalid choice" $Colors.Red
                Start-Sleep -Seconds 1
            }
        }
    }
} catch {
    Write-Color "`n[!] CRITICAL ERROR: $_" $Colors.Red
    Write-Color "[~] Check admin rights" $Colors.Yellow
    Read-Host "`nPress Enter to exit"
}
