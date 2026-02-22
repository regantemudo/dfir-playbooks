# 🔁 DNS Tunneling — C2 Communication via DNS

---

## Overview

DNS tunneling is a technique where attackers encode data inside DNS queries and responses to establish covert command-and-control (C2) channels. Because DNS traffic is rarely blocked at firewalls and is often not fully inspected, it provides a reliable exfiltration and C2 path even in heavily restricted environments.

---

## How DNS Tunneling Works

```
1. Attacker registers a domain they control (e.g., evil-c2[.]com)
2. Attacker sets up a DNS server on that domain
3. Victim machine is compromised with a DNS tunnel client
4. Client encodes commands/data as subdomains:
   GET_COMMAND.sessionid.evil-c2[.]com
5. Attacker's DNS server receives the query, decodes the data
6. Response contains encoded C2 commands in DNS TXT/A records
7. Client decodes the response and executes the command
```

**Result:** Full bidirectional C2 channel, entirely within DNS traffic.

---

## Why It's Effective

- DNS is almost never blocked outbound (breaks everything)
- DNS traffic is rarely fully logged or inspected
- Many security tools don't decode DNS query content
- Blends with high-volume normal DNS traffic
- Works even when HTTP/HTTPS is fully proxied and inspected

---

## Detection Indicators

### High-Value Signals

| Indicator | Description |
|---|---|
| **High query volume to single domain** | Legitimate domains don't require hundreds of subdomains per minute |
| **Long subdomain strings** | Tunneled data encoded as base32/base64 produces unusually long subdomains (>30 chars) |
| **High entropy subdomains** | Random-looking subdomain strings (e.g., `aGVsbG8gd29ybGQ.evil-c2.com`) |
| **Rare/new domains** | Recently registered domains with no prior reputation |
| **TXT record queries** | Unusually high TXT record lookups (often used for data return channel) |
| **NXDOMAIN flood** | Malformed queries probing a C2 domain before it responds |

### Detection Query (SIEM Pseudocode)

```
// Alert: Potential DNS Tunneling
WHERE dns.query.name MATCHES "[a-z0-9]{25,}\\..*"   // long subdomain
AND dns.query.count > 50 per 5 minutes              // high volume
AND dns.query.domain NOT IN known_good_domains
```

### Network-Level Detection

- **DNS query length:** Flag queries where subdomain length > 52 characters
- **Bytes per DNS session:** Legitimate DNS uses very few bytes; tunneling sessions transfer KB-MB
- **Unique subdomain ratio:** A domain generating many unique subdomains/minute is suspicious

---

## Common DNS Tunneling Tools (for Detection Reference)

| Tool | Use Case |
|---|---|
| `iodine` | Full IP-over-DNS tunnel |
| `dnscat2` | C2 channel via DNS |
| `dns2tcp` | TCP-over-DNS tunnel |
| `DNSExfiltrator` | Data exfiltration via DNS |

Knowing these tool names helps when searching for process names or signatures in endpoint telemetry.

---

## Defensive Recommendations

1. **DNS logging:** Enable full DNS query logging (not just failures) — this is the foundation for detection
2. **DNS RPZ (Response Policy Zones):** Block known malicious domains at the resolver level
3. **Passive DNS monitoring:** Track query patterns per host over time, not just individual queries
4. **DNS firewall:** Consider filtering DNS to only allow queries to your internal resolvers
5. **Alert on high-entropy subdomains:** Build SIEM rules for the patterns above

---

*See also: [C2 Patterns](../c2-patterns/README.md) | [Ransomware Intelligence](../../playbooks/ransomware-incident/)*
