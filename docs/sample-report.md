# 🕵️ Bond Investigation Report — `EDR-2026-04127`

**Decision:** 🔴 ESCALATE  ·  **Confidence:** High  ·  **Steps:** 2

> Malicious executable detected and quarantined

## Original Alert
**Type:** edr_malware  ·  **Severity:** high  ·  **Source:** CrowdStrike Falcon (EDR)

Endpoint agent flagged a file written to disk by a Word document macro and executed via a spawned PowerShell process. The file was quarantined. Signature-based and ML detection both fired.

## Findings Summary
EDR alert EDR-2026-04127 on Finance endpoint FIN-WKS-0473 (user j.harlow) describes a classic macro-delivered malware chain: WINWORD.EXE spawned a hidden, base64-encoded PowerShell process that wrote and executed invoice_update.exe from the user's Temp directory, which then attempted to contact secure-doc-update.ru / 185.220.101.47. Enrichment strongly corroborates malicious intent: (1) The dropped file SHA256 is flagged malicious by 65 engines on VirusTotal (live, non-mock source). (2) The external C2 IP 185.220.101.47 scores 100/100 on AbuseIPDB with 93 reports (live, non-mock source) and geolocates to AS60729 (Stiftung Erneuerbare Freiheit), an operator associated with Tor/anonymization infrastructure. (3) The contacted domain is a lookalike '.ru' domain ('secure-doc-update') matching the social-engineering invoice lure; mock threat-intel and WHOIS data (6-day-old, privacy-proxy registration) further suggest newly-stood-up malicious infrastructure.

## Rationale
Two independent LIVE (non-mock) sources confirm malicious key indicators — VirusTotal (65/n engines malicious on the file hash) and AbuseIPDB (100/100, 93 reports on the C2 IP). The behavioral chain (Office macro -> hidden encoded PowerShell -> dropped EXE -> external callout to a lookalike .ru domain) is textbook initial-access/malware execution. This is a true positive on a high-value Finance workstation, not a false positive. AUTO_CLOSE criteria are not remotely met (no benign corroboration); this requires human incident response.

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
| domain_reputation | `secure-doc-update.ru` | malicious | mock://domain-reputation | yes | Domain appears in threat-intel pulses (mock intel) |
| whois_lookup | `secure-doc-update.ru` | suspicious | mock://whois | yes | WHOIS: domain registered 6 days ago via a privacy proxy (mock) |
| dns_lookup | `secure-doc-update.ru` | unknown | mock://dns | yes | DNS A records: 203.0.113.10 (mock) |
| ip_reputation | `185.220.101.47` | malicious | https://www.abuseipdb.com | no | AbuseIPDB confidence score 100/100 (93 reports) |
| geoip_lookup | `185.220.101.47` | unknown | http://ip-api.com | no | GeoIP: Brandenburg an der Havel, Germany — Stiftung Erneuerbare Freiheit (AS60729 Stiftung Erneuerbare Freiheit) |

## Sources
- https://www.virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
- https://www.abuseipdb.com
- http://ip-api.com

## Next Steps
- Isolate/contain host FIN-WKS-0473 from the network pending IR review and confirm the EDR quarantine of invoice_update.exe held
- Decode the base64 PowerShell command (-enc payload) to extract full execution and any additional download URLs/persistence
- Hunt across the fleet for the file hash 275a021b... , the domain secure-doc-update.ru, and connections to 185.220.101.47
- Reset credentials for user j.harlow and review their activity for compromise/lateral movement
- Retrieve the originating Word document/email, identify other recipients of the phishing lure, and block sender/domain at the mail gateway
- Add secure-doc-update.ru and 185.220.101.47 to network blocklists / proxy denylist

---
_Generated 2026-06-13T15:03:35.770723+00:00_