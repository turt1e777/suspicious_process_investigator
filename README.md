# Suspicious Process Investigator

**Suspicious Process Investigator** is a PowerShell-based incident response tool designed to help security analysts/incident responders quickly triage and investigate suspicious processes on Windows systems.

It enriches local process data with hashing, parent/child relationships, network activity, and optional VirusTotal intelligence — making it ideal for SOC, DFIR, and lab environments.

---

## ✨ Features

- 🔍 Interactive process investigation by name
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
git clone https://github.com/<your-username>/suspicious-process-investigator.git
cd suspicious-process-investigator


