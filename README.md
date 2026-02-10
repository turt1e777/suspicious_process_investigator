# Suspicious Process Investigator by turt1e

**Suspicious Process Investigator** is a PowerShell-based incident response tool designed to help security analysts/incident responders quickly triage and investigate suspicious processes on Windows systems.

It enriches local process data with hashing, parent/child relationships, network activity, and optional VirusTotal intelligence — making it ideal for SOC, DFIR, and lab environments.

---

## ✨ Features

- 🔍 Interactive process investigation
- 🧬 Parent and child process enumeration
- 🌐 Active TCP network connection discovery
- 🔐 SHA256 file hash calculation
- 🧪 Optional VirusTotal hash enrichment
- 📊 Analyst-friendly console output
- 🔑 Secure API key handling via environment variables

---

## 🧰 Requirements

- Windows 10 / 11
- PowerShell 5.1 or PowerShell 7+
- Administrator privileges (recommended)
- Internet access (for VirusTotal lookups)

---

## 🚀 Installation 

Clone the repository:

```bash
git clone https://github.com/turt1e777/suspicious-process-investigator.git
cd suspicious-process-investigator
```

---

### ▶️ Usage

Run the script from an elevated PowerShell session:

```powershell
.\SuspiciousProcessInvestigator.ps1
```

When prompted, enter the name of the suspicious process:
```powershell
Enter the suspicious process name: maliciousprocessexample
```

---

### 🧪 VirusTotal Integration (Optional)

This tool supports VirusTotal hash lookups using the VirusTotal API.

1️⃣ Set your API key as an environment variable

Persistent (recommended):
```powershell
setx VT_API_KEY "YOUR_VIRUSTOTAL_API_KEY"
```
Restart PowerShell after setting the variable.





Temporary (current session only):
```powershell
$env:VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

2️⃣ The script will automatically detect and use the key

If the key is not set, VirusTotal lookups are skipped safely.

---

### 🔐 Security Notes
- Do NOT hardcode API keys in the script
- Environment variables keep secrets out of source control
- VirusTotal public API keys are rate-limited

---

### 🧠 Use Cases
- SOC alert triage
- Suspicious process validation
- Malware analysis lab enivronments
- Training & purple team exercises

---

### 🛣️ Roadmap

Planned enhancements:
- JSON/CSV export for Splunk / Microsoft Sentinel
- Option to kill the process after initial investigation

---
