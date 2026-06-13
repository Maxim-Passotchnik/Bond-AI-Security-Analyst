# 🕵️ Bond Investigation Report — `EDR-2026-04131`

**Decision:** 🟢 AUTO-CLOSE  ·  **Confidence:** High  ·  **Steps:** 2

> Heuristic flag on low-prevalence signed binary

## Original Alert
**Type:** edr_malware  ·  **Severity:** medium  ·  **Source:** Microsoft Defender for Endpoint

Defender's ML/heuristic engine flagged a freshly-deployed executable as potentially unwanted due to its low prevalence in the environment. The file is validly signed by Microsoft and was installed by the IT software-deployment tool (SCCM / ccmexec).

## Findings Summary
Defender raised a medium-severity heuristic alert on EndpointHealthAgent.exe on host ENG-WKS-1180 solely because the binary had low prevalence in the environment (freshly deployed). Enrichment of all key indicators returned benign/non-mock results: (1) SHA256 fde343...5755 is clean on VirusTotal (0/70 engines); (2) the only contacted domain, www.microsoft.com, is a ~35-year-established domain with no OTX threat pulses; (3) the contacted IP 13.107.42.14 has an AbuseIPDB confidence score of 0/100 and geolocates to Microsoft Corporation (AS8068). The file is validly signed by Microsoft and was installed by the IT software-deployment tool (SCCM/ccmexec.exe) via a standard silent-install command line. The alert content contained no prompt-injection attempts.

## Rationale
Multiple independent sources corroborate that the indicators are benign: a clean VirusTotal verdict on the file hash, a clean AbuseIPDB result plus Microsoft-owned ASN for the contacted IP, and a long-established WHOIS registration for the contacted domain. Combined with a valid Microsoft Authenticode signature and legitimate SCCM-driven deployment, the detection matches the classic profile of a low-prevalence false positive from Defender's ML/heuristic engine rather than a genuine threat. The decision criteria for AUTO_CLOSE (>=2 independent benign corroborations, all non-mock) are met.

## Indicators investigated
| Type | Value | Context |
|---|---|---|
| ip | `10.20.7.180` | host.ip |
| file_hash | `fde343ee184953c1fa1185abddeaa8be61c6acbebae4eb54db5d6b55b09a5755` | file.sha256 |
| domain | `www.microsoft.com` | network.contacted_domain |
| ip | `13.107.42.14` | network.contacted_ip |

## Evidence trail
| Tool | Query | Disposition | Source | Mock? | Finding |
|---|---|---|---|---|---|
| hash_reputation | `fde343ee184953c1fa1185abddeaa8be61c6acbebae4eb54db5d6b55b09a5755` | benign | https://www.virustotal.com/gui/file/fde343ee184953c1fa1185abddeaa8be61c6acbebae4eb54db5d6b55b09a5755 | no | VirusTotal: 0 engines flagged this file malicious |
| domain_reputation | `www.microsoft.com` | unknown | https://otx.alienvault.com | no | OTX: domain appears in 0 threat-intel pulse(s) |
| whois_lookup | `www.microsoft.com` | benign | https://who.is | no | WHOIS: long-established domain (registered ~12826 days ago) |
| ip_reputation | `13.107.42.14` | benign | https://www.abuseipdb.com | no | AbuseIPDB confidence score 0/100 (0 reports) |
| geoip_lookup | `13.107.42.14` | unknown | http://ip-api.com | no | GeoIP: Newark, United States — Microsoft Corporation (AS8068 Microsoft Corporation) |

## Sources
- https://www.virustotal.com/gui/file/fde343ee184953c1fa1185abddeaa8be61c6acbebae4eb54db5d6b55b09a5755
- https://otx.alienvault.com
- https://who.is
- https://www.abuseipdb.com
- http://ip-api.com

## Next Steps
- Confirm with IT/SCCM team that EndpointHealthAgent.exe is part of an approved software-deployment package for the Engineering fleet.
- Optionally submit the binary to Defender as a suppression/allow indicator to prevent repeat low-prevalence heuristic alerts as it rolls out to more hosts.
- No host containment or user (s.kovac) action required; close as benign false positive.

---
_Generated 2026-06-13T14:55:07.267436+00:00_