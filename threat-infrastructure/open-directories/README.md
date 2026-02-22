# 📂 Open Directory Exposures — Attacker Staging Servers

> All domains and IPs are defanged. Do not access these URLs.

---

## What Are Open Directories?

Open directories occur when a web server's directory listing is enabled, exposing all files in a folder publicly. Threat actors often inadvertently (or sometimes intentionally) expose their own staging infrastructure this way — providing defenders with valuable threat intelligence about payloads, tools, and campaign artifacts.

---

## Documented Exposure: APK & EXE Dump on `m-bureaux[.]fr`

### Summary

An open directory was discovered on a compromised French business website (`m-bureaux[.]fr`) being abused as a staging server for malicious APK (Android) and EXE (Windows) payloads.

### What Was Found

| File Type | Count | Purpose |
|---|---|---|
| `.apk` | Multiple | Malicious Android applications |
| `.exe` | Multiple | Windows malware droppers/payloads |
| `.php` | Multiple | Web shell access/maintenance scripts |

### Significance

- **APK presence** indicates a cross-platform campaign targeting both Android mobile devices and Windows desktops
- **Compromised legitimate domain** used as staging to evade domain reputation blocklists
- **Open listing** suggests the attacker prioritized speed of deployment over operational security

### Detection / Hunting

```
# Look for downloads from this domain in proxy logs
m-bureaux[.]fr

# Alert on .apk downloads from non-app-store domains
# Alert on .exe downloads from hosting/business websites (not software vendors)
```

### Defensive Takeaways

1. Compromised legitimate websites are commonly used as staging — domain reputation alone is insufficient
2. Proxy/DNS filtering should flag unexpected file type downloads (`.apk` from non-app-store sources)
3. EDR should alert on `.apk` files downloaded to Windows machines (they can be repackaged as executables)

---

## Open Directory Hunting Techniques

For defenders and researchers looking to identify similar exposures:

- **Shodan:** `http.title:"Index of /"` combined with file extension filters
- **Censys:** Similar directory listing queries
- **URLScan.io:** Historical scans of suspicious domains often capture directory listings
- **VirusTotal:** Check file hashes found in open directories for malware classification

---

*See also: [C2 Patterns](../c2-patterns/README.md) | [Malware Samples](../../playbooks/malware-infection/README.md)*
