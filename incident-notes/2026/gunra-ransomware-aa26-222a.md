# Gunra Ransomware (CISA AA26-222A)

**Date logged:** September 2026
**Type:** Threat intelligence note
**Source:** CISA joint advisory AA26-222A (10 Aug 2026)
**Full playbook:** [../../playbooks/ransomware-incident/gunra-ransomware-aa26-222a.md](../../playbooks/ransomware-incident/gunra-ransomware-aa26-222a.md)

## What happened
Gunra is a double-extortion ransomware-as-a-service that emerged in April 2025 from leaked Conti
source code and stood up a formal affiliate program ("Golden Community") in January 2026. On
10 August 2026, FBI, CISA, DC3, NSA, USSS, and Korea's KNPA published a joint advisory after
Gunra affiliates hit critical infrastructure across healthcare, finance, manufacturing,
government, and utilities worldwide.

## Why it matters
Entry is through unpatched internet-facing FortiGate and SSL-VPN appliances
(CVE-2024-55591, CVE-2025-24472). Affiliates steal data (OneDrive, SharePoint, databases, email),
delete Volume Shadow Copies, destroy backups, then encrypt with ChaCha20 + RSA-4096. It is a
patch-and-backup problem far more than a phishing one.

## Fast IOCs (defanged)
```text
Ransom note:  R3ADM3.txt
Extensions:   .ENCRT  .CRYPT  .GNRA
Rogue admin:  forticloud-sync   (FortiGate super-user)
Leak site:    lgiil72vkmdtbc3qv4tyq6wedyjxqr2qd4ze7xl2cxgerdnymxj7soqd[.]onion
IP pool:      23.239.119[.]2   103.125.234[.]14   86.54.28[.]216
Encryptor:    91f8fc7a3290611e28a35a403fd815554d9d856006cc2ee91ccdb64057ae53b0  (cryptor.exe)
```

## Note for responders
Preserve encrypted files on Linux hosts. The ELF variant seeds `rand()` with `time()`, which can
allow key reconstruction. Do not pay. See the full playbook for detection queries and the complete
IOC set.
