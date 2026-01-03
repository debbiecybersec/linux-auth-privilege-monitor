# linux-auth-privilege-monitor

A Linux authentication and privilege monitoring tool that analyzes system auth logs to detect suspicious login activity, sudo usage, and potential privilege escalation events.

---

## 📌 Overview

This project simulates a **SOC-style log analysis workflow** by parsing Linux authentication logs to identify risky authentication and privilege-related behaviors.

It is designed to help defenders detect:
- Abuse of sudo privileges
- Unauthorized privilege escalation
- Suspicious access to sensitive system files
- Indicators of post-compromise activity

---

## ⚙️ How It Works

1. Reads Linux authentication logs from `logs/auth.log`
2. Parses log entries related to:
   - `sudo` command execution
   - `su` (switch user) sessions
   - High-risk commands
3. Correlates activity per user
4. Generates a structured security report in `reports/privilege_report.txt`

---

## 🚨 Threat Scenarios Detected

- Unauthorized privilege escalation attempts
- Abuse of `sudo` for system modification
- Access to sensitive files such as `/etc/shadow`
- Suspicious use of tools often leveraged after compromise (e.g. `netcat`, `curl`, `bash`)
- Switching to root via `su`

---

## 🧪 Sample Report Output

---

## 🧠 MITRE ATT&CK Mapping

- **T1548** – Abuse Elevation Control Mechanism
- **T1059** – Command and Scripting Interpreter
- **T1078** – Valid Accounts

---

## 🛠️ Tools & Technologies

- Python 3  
- Linux (Kali / Ubuntu)  
- Log analysis  
- Regular expressions  
- Git & GitHub

---

## ⚠️ Limitations

- Operates on static log files (no real-time monitoring)  
- No SIEM integration  
- Pattern-based detection may miss novel techniques

---

## 🚀 Future Improvements

- Real-time monitoring using syslog  
- JSON or CSV output for SIEM ingestion  
- Email or Slack alerting  
- GeoIP enrichment  
- Docker deployment

---

## 🎯 Why This Project Matters

Privilege escalation is a critical step in most Linux-based attacks.  
This project demonstrates how defenders can detect early indicators of compromise by monitoring authentication and privilege usage patterns.
