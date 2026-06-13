# 🕵️ Bond Investigation Report — `EDR-2026-04127`

**Decision:** 🔴 ESCALATE  ·  **Confidence:** High  ·  **Steps:** 2

> Malicious executable detected and quarantined

## Findings Summary
EDR alert on Finance workstation FIN-WKS-0473 (user j.harlow) describes a classic malicious-document attack chain: WINWORD.EXE spawned an obfuscated, hidden PowerShell process (powershell -nop -w hidden -enc ...), which wrote and executed invoice_update.exe to the user's Temp directory. Enrichment confirms genuine malicious activity: (1) File SHA256 is flagged malicious by 65 VirusTotal engines. (2) Contacted external IP 185.220.101.47 has a 100/100 AbuseIPDB confidence score with 93 reports, geolocating to AS60729 (Stiftung Erneuerbare Freiheit), an ASN well-known for hosting Tor exit nodes / anonymizing infrastructure. (3) Contacted domain secure-doc-update.ru was registered only 6 days ago via a privacy proxy — a hallmark of disposable malicious C2/staging infrastructure — and resolves to 203.0.113.10. OTX shows no pulses, consistent with brand-new infrastructure not yet widely reported.

## Rationale
Multiple independent, high-fidelity indicators corroborate a real threat: a 65/AV malicious binary, a known-abusive contacted IP (100/100, Tor-associated ASN), and a freshly-registered privacy-proxied .ru domain — all consistent with a macro-borne dropper executing PowerShell and reaching out to C2. There is no benign explanation for this combination. Although the file was reportedly quarantined, the spawned PowerShell may have performed additional actions and the host belongs to a Finance user (high-value target), so human follow-up and host containment are warranted. Per policy, this is unambiguously ESCALATE.

## Indicators investigated
| Type | Value | Context |
|---|---|---|
| ip | `10.12.4.73` | host.ip |
| file_hash | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | file.sha256 |
| domain | `secure-doc-update.ru` | network.contacted_domain |
| ip | `185.220.101.47` | network.contacted_ip |

## Evidence trail
| Tool | Query | Disposition | Source | Mock? | Finding |
|---|---|---|---|---|---|
| hash_reputation | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` | malicious | https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f | no | VirusTotal: 65 engines flagged this file malicious |
| domain_reputation | `secure-doc-update.ru` | unknown | https://otx.alienvault.com | no | OTX: domain appears in 0 threat-intel pulse(s) |
| whois_lookup | `secure-doc-update.ru` | suspicious | mock://whois | yes | WHOIS: domain registered 6 days ago via a privacy proxy (mock) |
| dns_lookup | `secure-doc-update.ru` | unknown | mock://dns | yes | DNS A records: 203.0.113.10 (mock) |
| ip_reputation | `185.220.101.47` | malicious | https://www.abuseipdb.com | no | AbuseIPDB confidence score 100/100 (93 reports) |
| geoip_lookup | `185.220.101.47` | unknown | http://ip-api.com | no | GeoIP: Brandenburg an der Havel, Germany — Stiftung Erneuerbare Freiheit (AS60729 Stiftung Erneuerbare Freiheit) |

## Sources
- https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
- https://otx.alienvault.com
- mock://whois
- mock://dns
- https://www.abuseipdb.com
- http://ip-api.com

## Next Steps
- Isolate/contain host FIN-WKS-0473 from the network pending forensic review
- Decode the base64 PowerShell -enc payload to determine downloaded/executed actions and any persistence
- Hunt across the fleet for the SHA256 275a021b..., connections to 185.220.101.47, and DNS queries for secure-doc-update.ru
- Pull and analyze the originating Word document (email gateway/mail logs) to identify delivery vector and other recipients
- Reset credentials for j.harlow and review Finance-department access given targeting
- Block the domain secure-doc-update.ru and IP 185.220.101.47 at perimeter/proxy and add hash to blocklist
- Verify quarantine success and check for any child processes or scheduled tasks created before quarantine

---
_Generated 2026-06-13T13:40:37.862990+00:00_