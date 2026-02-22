# 🛡️ Regan Temudo — DFIR & Threat Intelligence Research

> **Defensive research repository.** All malware samples are defanged. See [DISCLAIMER.md](./DISCLAIMER.md) before use.

![Threat Intelligence](https://img.shields.io/badge/Focus-Threat%20Intelligence-red?style=flat-square&logo=security)
![DFIR](https://img.shields.io/badge/Domain-DFIR-blue?style=flat-square&logo=shield)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange?style=flat-square)
![Samples](https://img.shields.io/badge/Malware%20Samples-12%20Defanged-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Research-brightgreen?style=flat-square)

Practical Digital Forensics, Incident Response (DFIR), and Threat Intelligence research — built around **real-world campaigns observed in the wild.**

This is not a theoretical collection. Every playbook, sample, and write-up here comes from actual threat activity.

---

## ⚡ Quick Actions

> Jump straight to the most useful resources in this repo.

| Action | Link | What You'll Find |
|---|---|---|
| 🚨 **Respond to an incident right now** | [IR Playbooks →](./playbooks/) | Step-by-step containment procedures |
| 🔍 **Hunt for IOCs in your environment** | [IOC Index →](#-ioc-quick-reference) | IPs, hashes, domains, detection queries |
| 🧬 **Analyze a malware sample** | [Sample Analysis →](./playbooks/malware-infection/README.md) | Defanged PHP shells with behavior notes |
| 🗺️ **Map an attack to MITRE ATT&CK** | [MITRE Coverage →](#-mitre-attck-coverage) | Full technique index |
| 🏗️ **Investigate C2 infrastructure** | [Threat Infrastructure →](./threat-infrastructure/) | C2 patterns, RMM abuse, DNS tunneling |
| 📖 **Read a threat actor profile** | [Ransomware Intel →](./playbooks/ransomware-incident/) | Black Shrantac, Green Blood |
| 🛡️ **Build detection rules** | [Detection Queries →](#-detection-quick-reference) | SIEM/EDR queries ready to deploy |

---

## What's in Here

### 📋 Incident Response Playbooks (`/playbooks/`)

Step-by-step SOC-ready response procedures aligned with NIST and SANS IR methodology. Each playbook covers Detection → Triage → Containment → Eradication → Recovery → Lessons Learned.

| Playbook | Threat Type | Severity | MITRE Coverage |
|---|---|---|---|
| [Fake CAPTCHA → PowerShell Malware](./playbooks/malware-infection/fake-captcha-powershell-malware-91-84-125-16) | Fileless Malware / Social Engineering | 🔴 High | T1566, T1059.001, T1027, T1071.001 |
| [Phishing Incident](./playbooks/phishing-incident/) | Phishing / BEC | 🔴 High | T1566, T1078 |
| [Ransomware Response](./playbooks/ransomware-incident/) | Ransomware / Double Extortion | 🔴 Critical | T1486, T1490, T1041 |
| [Insider Threat](./playbooks/insider-threat/) | Insider / Data Exfiltration | 🟠 Medium-High | T1052, T1078, T1213 |
| [Cloud Security Incident](./playbooks/cloud-incident/) | Cloud / IAM Abuse | 🔴 High | T1078.004, T1530 |

---

### 🦠 Malware Samples (`/playbooks/malware-infection/`)

Defanged samples collected from active campaigns. All `.php` files renamed to `.php.sample` — **cannot execute** in this state.

| Sample | Type | Campaign |
|---|---|---|
| `cache.php.sample` | PHP Web Shell (File Manager) | Mass WordPress compromise |
| `shadow-bot.php.sample` | PHP Web Shell + DB tool | Targeted server compromise |
| `cleavable.php.sample` | Obfuscated PHP loader | C2 staging |
| `wordfencetenp.php.sample` | Malicious WP plugin disguise | Security plugin bypass |
| `lkdo11-16.php.sample` | Obfuscated droppers | Payload staging |
| `odcat17-110.php.sample` | Obfuscated droppers | Payload staging |

See the [malware-infection README](./playbooks/malware-infection/README.md) for full analysis notes.

---

### 🕵️ Threat Intelligence & Incident Notes (`/incident-notes/`)

Real-world threat investigations written in analyst format.

- **[Fake CAPTCHA PowerShell Campaign (91.84.125.16)](./incident-notes/2026/fake-captcha-powershell-malware-91-84-125-16)** — Active campaign abusing Windows Run dialog to execute fileless PowerShell malware

---

### 🏗️ Threat Infrastructure (`/threat-infrastructure/`)

| Category | Description |
|---|---|
| [C2 Patterns](./threat-infrastructure/c2-patterns/) | Shadow C2 panel and fake CAPTCHA campaign C2 (91.84.125.16) |
| [Open Directories](./threat-infrastructure/open-directories/) | Exposed attacker staging servers leaking APK/EXE payloads |
| [RMM Abuse](./threat-infrastructure/rmm-abuse/) | Malspam abusing GoToResolve / LogMeIn for remote access |
| [DNS Tunneling](./threat-infrastructure/dns-tunneling/) | DNS-based C2 communication patterns |

---

### 📊 Ransomware Intelligence

- **[Black Shrantac](./playbooks/ransomware-incident/)** — Double-extortion actor active Sep 2025–Jan 2026. 30+ victims across government, healthcare, utilities, financial services.
- **[Green Blood Ransomware](./playbooks/ransomware-incident/)** — Extension `.gblood`, known SHA-256 hashes, ransom note variants.

---

## 🎯 IOC Quick Reference

> Copy-paste ready for SIEM, firewall, or threat hunting. All IPs/domains are **defanged** — remove brackets before use.

### Malicious IPs
```
91.84.125[.]16        # Fake CAPTCHA PowerShell C2 — payload host (/big.txt)
5.9.228[.]188:5000    # Shadow C2 admin panel
```

### Malicious Domains
```
wertg-rewe[.]com      # cleavable.php loader C2 (obfuscated in octal)
stepmomhub[.]com      # cache.php WordPress mass-compromise receiver
```

### File Hashes (SHA-256)
```
365f2f4de5ac872ce5a1fe6fbbf382b936c1defc6d767a37f69b5df4188d9522   # shadow-bot PHP shell
05294c9970f365c92e0b0f1250db678dc356dbf418dba27bdd5eeb68487a7199   # Green Blood ransomware sample
```

### Ransomware File Extensions
```
.gblood    # Green Blood Ransomware
```

### Ransomware Note Filenames
```
RESTORE_FILES.txt
README.txt
DECRYPT_INSTRUCTIONS.txt
IMPORTANT_README.txt
HOW_TO_RECOVER_FILES.txt
```

---

## 🔎 Detection Quick Reference

> Ready-to-adapt queries for common SIEM/EDR platforms.

### PowerShell / Fileless Malware
```powershell
# Windows Event Log — ScriptBlock Logging (Event ID 4104)
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object { $_.Message -match "Invoke-Expression|iex\b|-enc\b|91\.84\.125\.16" }

# Sysmon / EDR — suspicious PowerShell launch
CommandLine contains "-enc" AND ParentProcess in ("outlook.exe","chrome.exe","msedge.exe","firefox.exe")
```

### Web Shell Detection
```bash
# Search for web shell indicators in web root
grep -rn "eval(base64_decode\|shell_exec\|system(\|passthru(\|root@xshikata\|create_wp_admin" /var/www/

# Alert on PHP process spawning shell
ParentProcess == "php-fpm" AND ChildProcess in ("bash","sh","cmd.exe","powershell.exe")
```

### C2 Network Hunting
```
# SIEM — outbound to known bad IPs
dst_ip IN ("91.84.125.16", "5.9.228.188") AND direction == "outbound"

# Proxy logs — suspicious path
http.uri_path == "/big.txt" AND http.method == "GET"

# Alert on port 5000 outbound from servers
dst_port == 5000 AND src_zone == "server_dmz"
```

### DNS Tunneling
```
# High-entropy subdomain detection
dns.query.name MATCHES "^[a-z0-9]{25,}\\..*$"
AND dns.query.count > 50 WITHIN 5m
AND dns.query.domain NOT IN (whitelist)
```

### Ransomware Indicators
```
# File extension monitoring
file.extension IN (".gblood") OR
file.name IN ("RESTORE_FILES.txt","DECRYPT_INSTRUCTIONS.txt","HOW_TO_RECOVER_FILES.txt")

# Mass file modification (ransomware encryption behavior)
file.write_count > 500 WITHIN 60s AND process.name NOT IN (backup_tools_whitelist)
```

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | ID | Covered In |
|---|---|---|---|
| Initial Access | Phishing | T1566 | Phishing Playbook, Fake CAPTCHA |
| Execution | PowerShell | T1059.001 | Fake CAPTCHA Playbook |
| Execution | User Execution | T1204 | RMM Abuse, Phishing |
| Persistence | Web Shell | T1505.003 | All PHP samples |
| Persistence | Remote Access Software | T1219 | RMM Abuse write-up |
| Defense Evasion | Obfuscated Files/Info | T1027 | cleavable, lkdo, odcat samples |
| Defense Evasion | Masquerading | T1036.005 | wordfencetenp sample |
| Defense Evasion | Deobfuscate/Decode | T1140 | shadow-bot sample |
| Credential Access | Valid Accounts | T1078 | cache.php, Insider Threat |
| Discovery | Remote System Discovery | T1018 | Insider Threat Playbook |
| Lateral Movement | Remote Services | T1021 | Ransomware Playbook |
| Exfiltration | Exfil Over C2 Channel | T1041 | Ransomware, Insider Threat |
| Exfiltration | DNS Tunneling | T1048.003 | DNS Tunneling write-up |
| Impact | Data Encrypted for Impact | T1486 | Ransomware Playbooks |
| Impact | Inhibit System Recovery | T1490 | Black Shrantac, Green Blood |
| Command & Control | Web Protocols | T1071.001 | Fake CAPTCHA C2 |
| Command & Control | Application Layer Protocol: DNS | T1071.004 | DNS Tunneling write-up |
| Command & Control | Remote Access Software | T1219 | RMM Abuse |

---

## Design Principles

- Real campaigns, not hypotheticals
- Defender-first — detection queries and response steps are the priority
- MITRE ATT&CK mapped across all playbooks
- SOC-ready structure for Tier 1–3 analysts

---

## Framework Alignment

NIST SP 800-61 · SANS PICERL · MITRE ATT&CK v14 · OWASP

---

## ⚠️ Disclaimer

All samples are defanged and stored for **defensive research only**. See [DISCLAIMER.md](./DISCLAIMER.md).

---

**Regan Temudo** | DFIR & Threat Intelligence  
[LinkedIn](https://linkedin.com/in/regan-temudo) · [GitHub](https://github.com/regantemudo)
