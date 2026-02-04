# WANTHRUST WiFi Toolkit (PowerShell Edition)

**Version:** 2.2
**Author:** [44](https://t.me/chanel441)
**Platform:** Windows 10/11
**Language:** PowerShell 5.1+

> ⚠️ **Legal Notice**
> This toolkit is intended **only for security auditing, education, and administration of networks you own or have explicit permission to test**. Unauthorized access, interception, or attacks against third‑party networks may be illegal in your jurisdiction. You are solely responsible for how you use this software.

---

## 📌 Overview

**WANTHRUST** is an all‑in‑one **Windows PowerShell WiFi and network auditing toolkit**. It wraps native Windows tools (`netsh`, `ipconfig`, `netstat`, etc.) and common security utilities (Wireshark, Nmap, Hashcat) into a **menu‑driven interface** for:

* WiFi network discovery and analysis
* Extraction and export of saved WiFi profiles
* Hotspot creation and configuration
* Basic security auditing and reporting
* Automated data collection for incident response

No kernel drivers or exploits are bundled — WANTHRUST focuses on **visibility, configuration, and analysis**, not bypassing OS protections.

---

## ✨ Features

### 🔍 WiFi Enumeration

* Scan nearby WiFi networks (BSSID mode)
* Signal strength, channel, authentication, encryption
* Automatic detection of **open / WEP / weak networks**
* Export results to **TXT / CSV**

### 🔐 Saved WiFi Password Extraction

* Enumerates stored WLAN profiles
* Extracts clear‑text keys (when permitted by Windows)
* Output formats:

  * CSV
  * TXT
  * JSON

### 📤 WiFi Profile Export

* Export all WLAN profiles as XML
* Optional ZIP archive
* Includes passwords (key=clear)
* Import‑ready on another Windows system

### 📡 Hotspot / Access Point Setup

* Regular hotspot (WPA2)
* Open hotspot (no password)
* Network cloning (SSID impersonation)
* Step‑by‑step setup instructions

### 🧪 Network Attacks (Guided / Informational)

* WEP detection guidance
* Open network analysis workflow
* Deauthentication overview (requires Linux / monitor mode)
* Dictionary cracking workflow (Hashcat)

> ⚠️ These sections **do not bypass Windows limitations** and mostly provide guidance and tool chaining.

### 📊 Traffic Analysis

* Integration checks for:

  * Wireshark / tshark
  * Nmap
* Packet capture (PCAP)
* Network discovery scans

### 🤖 Auto Data Collection

* System information
* Network configuration
* WiFi profiles and scans
* Driver inventory
* Automatic ZIP report generation

### 🛡️ Security Audit & Recommendations

* WiFi security checks
* Best‑practice recommendations
* Secure password generator
* Report export

---

## 🧰 Requirements

### Mandatory

* Windows 10 / 11
* PowerShell 5.1 or newer

### Recommended (Optional)

* **Administrator privileges** (for full functionality)
* Wireshark (Npcap)
* Nmap
* Hashcat
* Winget (for dependency installation)

---

## 🚀 Installation

1. Clone or download the repository:

   ```powershell
   git clone https://github.com/wqwda44/WANTHRUST
   cd WANTHRUST
   ```

2. Allow script execution (temporary):

   ```powershell
   powershell -ExecutionPolicy Bypass -File WANTHRUST.ps1
   ```

3. (Optional) Run PowerShell **as Administrator** for full access.

---

## ▶️ Usage

Launch from PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File WANTHRUST.ps1
```

Navigate using the interactive menu:

```
[1] Scan WiFi networks
[2] Extract saved WiFi passwords
[3] Export WiFi profiles
[4] Create hotspot
[5] Attack weak networks
[6] Traffic analysis
[7] Auto data collection
[8] Network security audit
[9] Settings and utilities
[0] Exit
```

---

## 📂 Output Files

WANTHRUST generates timestamped files such as:

* `WiFi_Networks_YYYYMMDD_HHMMSS.csv`
* `WiFi_Passwords_YYYYMMDD_HHMMSS.json`
* `WiFi_Profiles_YYYYMMDD_HHMMSS.zip`
* `Collection_YYYYMMDD_HHMMSS.zip`

⚠️ **Some outputs contain clear‑text credentials. Store and delete responsibly.**

---

## 🔒 Security Notes

* Exported XML profiles include WiFi passwords
* Packet captures may contain sensitive data
* Always clean temporary files after audits
* Use encrypted storage when handling reports

---

## ❗ Limitations

* Windows does **not** support monitor mode or packet injection natively
* Deauth and handshake capture require:

  * Linux
  * Compatible USB WiFi adapter
* Some features are informational only

---

## 🧭 Roadmap (Ideas)

* PowerShell module packaging
* HTML audit reports
* Integration with WSL tools
* Plugin system
* GUI wrapper (WPF)

---

## 📜 Disclaimer

This project is provided **as‑is**, without warranty of any kind. The authors are not responsible for misuse, data loss, or legal consequences resulting from use of this software.

---

## ⭐ Credits

* Microsoft `netsh` WLAN API
* Wireshark / Npcap
* Nmap Project
* Hashcat

---

## 🔗 Repository

GitHub: [https://github.com/wqwda44/WANTHRUST](https://github.com/wqwda44/WANTHRUST)

Author: [44Сhannel](https://t.me/chanel441)

---

**Use responsibly. Audit smart. Stay legal.**
