## Gunra Ransomware (Double Extortion RaaS)

##### Author: Regan Temudo
##### Type: Threat Intelligence / Incident Response Playbook
##### Status: Active RaaS, tracked in joint advisory CISA AA26-222A (10 Aug 2026)

### Threat Class
Ransomware as a Service (RaaS) · Double Extortion · Conti-derived encryptor

### Severity
**Critical** (Data encryption + data theft + backup destruction)

---

## Threat Profile

Gunra first appeared in **April 2025** as a double-extortion ransomware variant built from the
leaked **Conti** source code. In **January 2026** the operators launched a formal RaaS affiliate
program on dark web forums, recruiting affiliates under aliases including "Golden Community".

The operation pairs file encryption with the threat of public data leaks on a dedicated leak
site (DLS). Victims span healthcare and public health, financial services and insurance, critical
manufacturing, transportation and logistics, government services, utilities, academia, media,
and retail, across the Americas, Europe, the Middle East, Africa, and Asia Pacific.

Encryption uses a hybrid **ChaCha20 + RSA-4096** scheme with multi-threaded, parallel processing.
There are Windows PE and Linux ELF encryptors. Note the Linux ELF variant seeds `rand()` with
`time()`, a weakness that can allow key reconstruction, so encrypted files and timestamps must be
preserved rather than deleted.

---

## 1 - Detection & Identification

### Primary Detection Signals
- Ransom note **`R3ADM3.txt`** dropped into affected directories
- Files renamed with extension **`.ENCRT`** (also seen: `.CRYPT`, and `.GNRA` on Linux)
- Volume Shadow Copy deletion via **WMIC** shortly before mass encryption
- Bursts of administrative activity in the **10 PM to 6 AM** window
- Newly created FortiGate super-admin account named **`forticloud-sync`**
- Mass file writes across all drive letters (recursive enumeration A to Z)

### Example Detection Queries
```
# Mass encryption behavior
file.extension IN (".ENCRT", ".CRYPT", ".GNRA")
  OR file.name == "R3ADM3.txt"
  AND file.write_count > 500 WITHIN 60s

# Shadow copy deletion (inhibit recovery)
process.name IN ("wmic.exe", "vssadmin.exe")
  AND command_line MATCHES "shadowcopy delete|delete shadows"

# FortiGate exploit / rogue account (initial access)
fortigate.event == "admin account created"
  AND account.name == "forticloud-sync"
```

---

## 2 - Initial Triage (First 15 Minutes)

### Analyst Actions
- Confirm the encryption extension and locate a copy of `R3ADM3.txt`
- Identify patient-zero host and the internet-facing appliance used for entry
- Capture hostname, account names, first encrypted timestamp, and edge device logs
- Do NOT delete encrypted files (Linux ELF keys may be recoverable)
- Do NOT wipe or reimage before forensic capture

### Decision Point
Confirmed mass encryption or a `forticloud-sync` account creation triggers a **Critical** incident.

---

## 3 - Containment

### Endpoint & Identity Containment
- Isolate encrypting hosts and any host touching the FortiGate / SSL-VPN appliance
- Disable the rogue `forticloud-sync` account and any compromised privileged accounts
- Force password reset plus MFA re-enrollment for domain and VPN accounts (OTP bypass was observed)
- Revoke active VDI and SSL-VPN sessions (session cookie theft was observed)

### Network Containment
- Patch or take offline FortiOS / FortiProxy appliances vulnerable to CVE-2024-55591 and CVE-2025-24472
- Block known Gunra infrastructure at firewall, proxy, and DNS
- Restrict SMB (445) and RDP (3389) lateral movement between segments
- Protect backup infrastructure by cutting production access to backup networks

---

## 4 - Investigation & Analysis

### Host-Based Analysis
- Review Security and PowerShell logs for Impacket usage (`secretsdump.py`, `psexec.py`, `smbclient.py`)
- Hunt for credential dumping from domain controllers (NTDS extraction)
- Check for Mimikatz, Sliver C2, AnyDesk / MobaXterm, and OpenSSH tunneling
- Look for native API file enumeration (`FindFirstFileW` / `FindNextFileW`) and `IsDebuggerPresent`

### Network & Exfiltration Analysis
- Review outbound transfers to **Mega**, FTP via **FileZilla**, and **RClone** cloud syncs
- Correlate large OneDrive / SharePoint pulls with the `main.exe` exfiltration tool
- Match edge-device logins against the IOC IP pool below

---

## 5 - Eradication

### Required Actions
- Rebuild compromised hosts from known-good media
- Remove all attacker accounts and rotate every privileged credential (assume full AD compromise)
- Reset the FortiGate configuration and rebuild affected appliances after patching
- Use CISA's Eviction Strategies Tool (Playbook-NG + COUN7ER) for systematic actor removal

### Validation
- Confirm no residual outbound traffic to Gunra infrastructure
- Confirm no new rogue accounts or scheduled persistence

---

## 6 - Recovery

### System Restoration
- Restore from offline, immutable, tested backups only
- Rebuild identity trust (Kerberos, KRBTGT double reset) after AD compromise
- Monitor restored systems closely for 72+ hours

### Business Validation
- Assess scope of stolen data (business documents, PII, databases, email)
- Prepare regulatory and breach-notification steps for the double-extortion data theft
- Do NOT pay the ransom (FBI / CISA guidance)

---

## 7 - Post-Incident Actions

### Lessons Learned
- Root cause is almost always an unpatched internet-facing appliance
- Validate that edge-device patching and backup immutability are enforced, not assumed

### Preventive Controls
- Prioritized patching of FortiOS / FortiProxy and all VPN gateways
- Enforce phishing-resistant MFA on VPN, webmail, and privileged accounts
- Segment critical infrastructure (DCs, VDI, databases, NAS)
- Restrict command-line and scripting for non-admin users
- Maintain 90+ days of edge and DC logs for retrospective hunting

---

## 8 - Indicators of Compromise (IOCs)

> All indicators are defanged. Remove brackets before use. Source: CISA AA26-222A.

### Ransom Note & Encryption
```text
Ransom note:   R3ADM3.txt
Extensions:    .ENCRT  .CRYPT  .GNRA
Negotiation:   qTox + Tor client portal
```

### Leak Sites (Tor / clearnet)
```text
gunrabxbig445sjqa535uaymzerj6fp4nwc6ngc2xughf2pedjdhk4ad[.]onion   # DLS Apr 2025 to Feb 2026
lgiil72vkmdtbc3qv4tyq6wedyjxqr2qd4ze7xl2cxgerdnymxj7soqd[.]onion   # DLS Mar 2026 to present
datapub[.]news                                                     # clearnet mirror (Jun to Jul 2025)
```

### Malicious IPs
```text
23.239.119[.]2      # Gunra server pool
23.239.119[.]6      # Gunra server pool
86.54.28[.]216      # exfil staging
103.125.234[.]14    # command node
70.36.99[.]82       # proxy / relay
91.201.66[.]146     # infrastructure
```

### File Hashes (SHA-256)
```text
2dc70a12d158d437e45a55b1d52f3d61c6082a1e1667573302ba3b62813e2751   # main.exe  (OneDrive/SharePoint exfil)
834efe9b392c6c000877ea5613a079445affc16fe8af5997d68c55cafc95e5d1   # main.exe  (OneDrive/SharePoint exfil)
91f8fc7a3290611e28a35a403fd815554d9d856006cc2ee91ccdb64057ae53b0   # cryptor.exe (encryptor)
a82e496b7b5279cb6b93393ec167dd3f50aff1557366784b25f9e51cb23689d9   # msmp.exe
```

### Rogue Account
```text
forticloud-sync   # attacker-created FortiGate super-admin (CVE-2024-55591 / CVE-2025-24472)
```

### Negotiation Emails
```text
a00f105546345756@proton[.]me
4569f6322bc3b22e9@proton[.]me
6449a3c1e612168526@proton[.]me
ilovemycubscout@gmail[.]com
```

---

## 9 - MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Windows Management Instrumentation | T1047 |
| Persistence | External Remote Services | T1133 |
| Privilege Escalation | Valid Accounts: Domain Accounts | T1078.002 |
| Defense Evasion | Inhibit System Recovery (VSS delete) | T1490 |
| Credential Access | OS Credential Dumping: NTDS | T1003.003 |
| Credential Access | MFA Modification | T1556.006 |
| Lateral Movement | Remote Desktop Protocol | T1021.001 |
| Lateral Movement | SMB / Admin Shares | T1021.002 |
| Lateral Movement | Pass-the-Hash / Pass-the-Ticket | T1550.002 / T1550.003 |
| Collection | Archive Collected Data | T1560 |
| Exfiltration | Exfil to Cloud Storage (Mega) | T1567.002 |
| Impact | Data Encrypted for Impact | T1486 |

---

## 10 - Summary

Gunra is a Conti-derived, double-extortion RaaS that gets in through unpatched FortiGate and
SSL-VPN appliances, steals data before encrypting with ChaCha20 + RSA-4096, and destroys backups
to block recovery. The single most effective control is fast edge-device patching (CVE-2024-55591,
CVE-2025-24472) backed by offline immutable backups and MFA on remote access.

---

### Source
CISA joint advisory **AA26-222A**, "#StopRansomware: Gunra Ransomware" (FBI, CISA, DC3, NSA, USSS,
KNPA), released 10 August 2026.
https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a

### Owner
SOC / Incident Response

### Review Cycle
Quarterly or on new Gunra sightings
