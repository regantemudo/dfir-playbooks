# APT36 / Transparent Tribe - SecureServer C2 Panel Exposure

**Threat Actor:** APT36 (Transparent Tribe, ProjectM, COPPER FIELDSTONE)  
**Category:** Nation-State / Espionage  
**Origin:** Pakistan-nexus  
**Targets:** Indian government, military, defense contractors, educational institutions  
**Severity:** 🔴 High  
**MITRE Techniques:** T1071.001, T1102, T1090, T1583.001, T1566

---

## Overview

A FOFA query surfaced exposed **SecureServer** login panels attributed to APT36 (Transparent Tribe) C2 infrastructure. These panels are used to manage implant callbacks and are typically deployed as part of the group's custom RAT ecosystem most notably **CrimsonRAT** and **ObliqueRAT**.

The panels were exposed publicly at time of discovery, allowing passive infrastructure mapping without direct interaction.

---

## FOFA Query

```
title=="SecureServer - Login"
```

**FOFA link:** https://en.fofa.info/result?qbase64=dGl0bGU9PSJTZWN1cmVTZXJ2ZXIgLSBMb2dpbiI=

> ⚠️ For research and detection purposes only. Do not interact with or authenticate to any identified C2 infrastructure.

---

## Identified Infrastructure (C2 Panels)

| Indicator | Type | Notes |
|---|---|---|
| `delhibellyindia[.]com` | Domain | SecureServer C2 panel |
| `2.56.10[.]46` | IP | SecureServer C2 panel |
| `45.13.225[.]22` | IP | SecureServer C2 panel |

> All indicators are **defanged**. Remove brackets before use in detection tooling.

---

## IOCs — Copy-Paste Ready

```
# Defanged - remove brackets before use

# Domains
delhibellyindia[.]com

# IPs
2.56.10[.]46
45.13.225[.]22
```

---

## Threat Actor Background

**APT36 (Transparent Tribe)** is a Pakistan-linked advanced persistent threat group active since at least 2013. The group is primarily focused on espionage against:

- Indian government ministries and defense sector
- Military personnel and contractors
- Educational institutions in India and Afghanistan

**Key tooling attributed to APT36:**

| Tool | Type | Notes |
|---|---|---|
| CrimsonRAT | Remote Access Trojan | Primary implant; .NET-based |
| ObliqueRAT | Remote Access Trojan | Used in 2020–2021 campaigns |
| CapraRAT | Android RAT | Mobile targeting of Indian officials |
| Mythic (repurposed) | C2 Framework | Observed in more recent infrastructure |

**Delivery:** Primarily phishing via weaponized Office documents, macro-laced attachments, and fake government-themed decoy files. The group has also leveraged fake VPN apps and trojanized Android APKs to target mobile devices.

---

## Infrastructure Analysis

The **SecureServer** panel branding is consistent with APT36's use of commercial or semi-commercial C2 tooling layered over custom implant infrastructure. The domain `delhibellyindia[.]com` follows the group's documented pattern of registering India-themed lure domains to blend in with expected traffic from targets.

**Registration pattern to watch:**
- India-themed domain names (geography, government ministry names, cultural references)
- Cheap or bulletproof hosting in Eastern Europe / AS ranges linked to prior APT36 campaigns
- Short TTLs and frequent infrastructure rotation following exposure

---

## Detection Queries

### Network - Outbound to known C2 IPs

```spl
# Splunk / generic SIEM
dst_ip IN ("2.56.10.46", "45.13.225.22")
AND direction == "outbound"
```

```kql
# Microsoft Sentinel / KQL
NetworkConnectionEvents
| where RemoteIP in ("2.56.10.46", "45.13.225.22")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

### DNS - Resolution of known bad domain

```spl
# Splunk
index=dns query="delhibellyindia.com"
| stats count by src_ip, query
```

```kql
# Sentinel
DnsEvents
| where Name contains "delhibellyindia.com"
| project TimeGenerated, Computer, ClientIP, Name
```

### Proxy / Web - SecureServer panel login path

```spl
# Look for direct panel access attempts (indicates internal pivot or insider)
http.uri_path IN ("/login", "/admin/login") 
AND (http.host == "delhibellyindia.com" OR dst_ip IN ("2.56.10.46", "45.13.225.22"))
```

### CrimsonRAT Beacon Pattern (host-based)

```spl
# Suspicious .NET process making outbound C2 connections
process.name IN ("msbuild.exe", "regsvcs.exe", "regasm.exe")
AND network.direction == "outbound"
AND NOT dst_ip IN (internal_cidr_whitelist)
```

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Relevance |
|---|---|---|---|
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | SecureServer panel communication |
| Command & Control | Web Service | T1102 | Infrastructure masquerading |
| Command & Control | Proxy | T1090 | C2 routing through exposed panels |
| Resource Development | Acquire Infrastructure: Domains | T1583.001 | India-themed domain registration pattern |
| Initial Access | Phishing | T1566 | Primary APT36 delivery vector |

---

## Hunting Recommendations

1. **Block and sinkhole** the identified IPs and domain at perimeter firewall and DNS resolver level.
2. **Hunt retrospectively** in proxy, DNS, and NetFlow logs for any historical connections to these indicators - implants may have been active before panel exposure.
3. **Scan your internet-facing infrastructure** for exposed admin panels matching `title=="SecureServer - Login"` to identify any internal assets mistakenly exposed.
4. **Correlate with CrimsonRAT IOCs** - if you find connections to these panels, pivot to look for `.NET`-based lateral movement and credential harvesting artifacts on the affected host.
5. **Monitor for India-themed domain registrations** if you are in a targeted sector - this actor registers fresh domains per campaign.

---

## References

- [APT36 - MITRE ATT&CK Group G0134](https://attack.mitre.org/groups/G0134/)
- [Transparent Tribe Targets Education Sector — Cisco Talos](https://blog.talosintelligence.com/transparent-tribe-targets-education/)
- [CrimsonRAT Analysis - Zscaler ThreatLabz](https://www.zscaler.com/blogs/security-research/apt36-uses-new-ttps-and-builds-on-existing-malware-targets-india)

---

## Credits

IOC source via threat intelligence sharing on social media. Infrastructure confirmed via FOFA passive scanning.

> **Disclaimer:** All indicators are defanged and shared for defensive research purposes only. See [DISCLAIMER.md](../DISCLAIMER.md).

---

*Regan Temudo | DFIR & Threat Intelligence*
