# 🖥️ RMM Abuse — Malspam Campaign Using Legitimate Remote Management Tools

## Campaign Summary

**Title:** Malspam Campaign Abusing Microsoft Outlook to Deploy LogMeIn GoToResolve RMM  
**Type:** Malspam / RMM Abuse / Initial Access  
**Status:** Documented

---

## Overview

This campaign abuses **legitimate Remote Monitoring and Management (RMM) software** — specifically LogMeIn's GoToResolve — to establish persistent remote access to victim systems. Because the attacker uses a legitimate, signed tool, many AV and EDR solutions do not alert on the RMM software itself.

The delivery mechanism exploits **Microsoft Outlook's mailto: URI handler** to pre-populate a phishing email with a malicious payload link, reducing friction for the victim.

---

## Attack Flow

```
1. Victim receives phishing email with "invoice" or "support" lure
2. Email contains a malicious link using mailto: or direct download
3. Victim downloads and installs GoToResolve (legitimate RMM tool)
4. Attacker gains full remote desktop access to victim machine
5. Attacker uses access for data theft, lateral movement, or ransomware staging
```

---

## Why RMM Abuse is Effective

- **Signed binaries** — RMM tools are code-signed by legitimate vendors; AV doesn't flag them
- **Legitimate network traffic** — C2 communication goes through the vendor's own cloud infrastructure (e.g., `goto.com`), which is typically whitelisted
- **No malware on disk** — from a forensic perspective, the "malware" is indistinguishable from legitimate remote support software
- **Plausible deniability** — victims often believe they are installing legitimate IT support software

---

## Tools Observed in RMM Abuse Campaigns

| Tool | Vendor | Commonly Abused Via |
|---|---|---|
| GoToResolve | LogMeIn | Malspam, fake IT support |
| AnyDesk | AnyDesk GmbH | Tech support scams |
| ScreenConnect | ConnectWise | MSP compromise |
| TeamViewer | TeamViewer SE | Fraud, BEC follow-up |
| Atera | Atera Networks | MSP supply chain |

---

## Detection

**Endpoint:**
- Alert on installation of RMM software not in your approved software inventory
- Monitor for `goto_resolve`, `anydesk`, `screenconnect` process names initiated by non-IT users
- Check parent process: RMM installed by browser process or email client is a strong indicator

**Network:**
- Outbound connections to RMM vendor cloud infrastructure from unexpected hosts
- DNS queries for `*.goto.com`, `*.anydesk.com`, `*.connectwise.com` from servers or non-IT endpoints

**Email:**
- `mailto:` URIs in HTML emails (unusual for legitimate correspondence)
- Attachments with `.exe` or links to executable download pages disguised as invoices

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Execution | User Execution | T1204.002 |
| Command & Control | Remote Access Software | T1219 |
| Persistence | Remote Access Software | T1219 |

---

## Defensive Recommendations

1. **Maintain an approved RMM software list** — alert on any unapproved RMM installation
2. **Block installation of unsigned or non-whitelisted remote access tools** via endpoint policy
3. **Email gateway: flag `mailto:` URI abuse** in HTML email bodies
4. **User awareness:** Employees should never install software prompted by an unsolicited email
5. **Network segmentation:** Limit which hosts can initiate outbound RMM connections

---

*See also: [C2 Patterns](../c2-patterns/README.md) | [Phishing Playbook](../../playbooks/phishing-incident/)*
