# 🏗️ C2 Patterns — Command & Control Infrastructure Analysis

> All IP addresses and domains are **defanged** using bracket notation (e.g., `91.84.125[.]16`) to prevent accidental navigation or click-through.

---

## Documented C2 Infrastructure

### Campaign 1: Fake CAPTCHA PowerShell Malware

| Attribute | Value |
|---|---|
| **IP** | `91.84.125[.]16` |
| **Payload Path** | `/big.txt` |
| **Protocol** | HTTP |
| **Execution Method** | `Invoke-Expression` (fileless, in-memory) |
| **Delivery Vector** | Fake reCAPTCHA overlay → Windows Run dialog → PowerShell |

**How it works:**

The C2 hosts a plaintext PowerShell script at `/big.txt`. The victim is socially engineered into running a command that fetches and executes this script entirely in memory using `Invoke-Expression` — leaving minimal disk artifacts and bypassing many AV solutions.

**Why this C2 design is effective:**
- HTTP on port 80 blends with normal web traffic
- Plaintext payload is easy to rotate (attacker just updates `big.txt`)
- No malware binary ever touches disk
- Single IP makes takedown simple, but payload can be re-hosted instantly

**Detection:**
```
Event ID 4104 (ScriptBlock Logging): contains "Invoke-Expression" OR "iex"
Event ID 4688 (Process Creation): powershell.exe with "-enc" argument
Network: Outbound HTTP GET to /big.txt on non-standard IPs
```

---

### Campaign 2: Shadow C2 Panel

| Attribute | Value |
|---|---|
| **IP** | `5.9.228[.]188` |
| **Port** | `5000` |
| **Protocol** | HTTP |
| **SHA-256** | `365f2f4de5ac872ce5a1fe6fbbf382b936c1defc6d767a37f69b5df4188d9522` |
| **VirusTotal** | [View Report](https://www.virustotal.com/gui/file/365f2f4de5ac872ce5a1fe6fbbf382b936c1defc6d767a37f69b5df4188d9522) |
| **Classification** | Trojan / Web Shell C2 Panel |

**Description:**

This infrastructure hosts a web-based C2 administration panel accessible on port 5000. The associated web shell (`shadow-bot.php.sample`) communicates with this endpoint. Port 5000 is atypical for web traffic and should be blocked or alerted at the firewall level for outbound connections from servers.

**Detection:**
```
Network: Outbound TCP to port 5000 from web servers
Firewall: Alert on any server-initiated connections to 5.9.228[.]188
```

---

## C2 Pattern Analysis

Across the documented campaigns, several patterns emerge:

**Infrastructure Characteristics:**
- Use of bulletproof hosting (Eastern European IP ranges)
- Low-cost VPS providers with minimal abuse response
- Short-lived infrastructure rotated frequently after detection
- HTTP preferred over HTTPS (easier to inspect payload, rotate content)

**Payload Delivery Patterns:**
- Fileless execution preferred (PowerShell, `eval()`, `Invoke-Expression`)
- Base64 and AES encoding used to obfuscate second-stage payloads
- Two-stage delivery common: loader fetches actual payload from C2

**Evasion Techniques Observed:**
- Plaintext payloads hosted on C2 (no file to scan on victim machine)
- Obfuscated PHP with goto-chains, hex encoding, dynamic function names
- Legitimate-looking file names (`big.txt`, `cache.php`, `wordfencetenp.php`)
- Encryption of C2 comms using AES-256-CBC with key from request parameters

---

## Defensive Recommendations

1. **Block outbound HTTP to non-CDN IPs** from web servers — servers should not be initiating HTTP requests to random IPs
2. **Enable PowerShell ScriptBlock Logging** (Event ID 4104) and alert on `Invoke-Expression` with encoded payloads
3. **Firewall rule: alert on port 5000 outbound** from any server
4. **SIEM rule: PHP process spawning child processes** (web shell command execution indicator)
5. **Monitor for `/big.txt` in outbound HTTP requests** — unusually generic path for a legitimate resource

---

*See also: [Fake CAPTCHA Playbook](../../playbooks/malware-infection/fake-captcha-powershell-malware-91-84-125-16) | [Malware Samples](../../playbooks/malware-infection/README.md)*
