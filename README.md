# Bond — AI Security Analyst 🕵️

> An autonomous AI agent that investigates security alerts like a Tier-1 SecOps analyst —
> extracting indicators, querying threat-intel & OSINT tools, reasoning over the evidence
> with the **Claude API**, and reaching a defensible verdict: **Auto-Close** or **Escalate**,
> backed by a structured, sourced report.

> **Status:** 🚧 Under active development. This is the project scaffold + architecture
> (PR #1). The tool layer, agent loop, and reporting land in subsequent PRs — see the roadmap below.

---

## What it does

Given a security alert (EDR malware detection, suspicious login, phishing email, …), Bond:

1. **Normalizes** the alert and **extracts IOCs** (file hashes, IPs, domains, URLs, users, hosts).
2. **Autonomously investigates** — Claude decides which tools to query and when it has enough context.
3. **Reaches a verdict** — `AUTO_CLOSE` (benign / false positive) or `ESCALATE` (hand to a human).
4. **Produces a structured report** (JSON **and** Markdown) with:
   - **Findings Summary** · **Confidence Level** · **Sources** · **Next Steps** · full evidence trail & rationale.

Because alert content and fetched threat-intel are attacker-influenced, Bond is **hardened
against prompt injection**: untrusted data is sanitized at every trust boundary, the agent
fails *safe* (toward escalation), and an injection attempt is itself treated as a malicious
signal. See **[ARCHITECTURE.md §5](ARCHITECTURE.md)** for the guardrail model.

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full system design, scaling plan, and testing strategy.

## Tooling (free-first, pluggable)

Every tool uses the **real API if its key is set in `.env`**, otherwise falls back to a
realistic **mock** — so Bond always runs end-to-end, and gets richer as you add keys.

| Capability | Provider(s) | Key? |
|---|---|---|
| File / hash reputation | VirusTotal, abuse.ch MalwareBazaar | free tier |
| IOC lookup (IP/domain/hash/URL) | abuse.ch ThreatFox | free |
| IP reputation | AbuseIPDB | free tier |
| Threat-intel pulses | AlienVault OTX | free |
| WHOIS / DNS / GeoIP | `python-whois`, `dnspython`, ip-api.com | **none** |
| Web / news search | DuckDuckGo (none) · Brave (optional) | none / optional |

Only the **Claude API key is required**.

## Setup

```bash
# 1. Clone
git clone https://github.com/Maxim-Passotchnik/Bond-AI-Security-Analyst.git
cd Bond-AI-Security-Analyst

# 2. Create a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure secrets
cp .env.example .env
#   -> paste your ANTHROPIC_API_KEY (required)
#   -> optionally add free threat-intel keys to upgrade tools from mock to live
```

## Usage

> ⏳ CLI entrypoint arrives in PR #4. Planned interface:

```bash
# Investigate a sample alert
python -m src.main --alert alerts/edr_malware_malicious.json

# Try the benign case (should Auto-Close)
python -m src.main --alert alerts/edr_malware_benign.json
```

## Sample alerts

Ready-to-run fixtures live in [`alerts/`](alerts/):

| File | Type | Expected outcome |
|---|---|---|
| `edr_malware_malicious.json` | EDR malware (flagship) | **Escalate** |
| `edr_malware_benign.json` | EDR heuristic FP | **Auto-Close** |
| `suspicious_login.json` | Identity / impossible-travel | Escalate |
| `phishing_email.json` | Phishing / credential harvest | Escalate |

## Project layout

```
Bond-AI-Security-Analyst/
├── README.md
├── ARCHITECTURE.md          # system design (Task 2 deliverable)
├── requirements.txt
├── .env.example
├── src/
│   ├── models.py            # typed state + report dataclasses
│   ├── guardrails.py        # AI-security trust-boundary enforcement    (PR #2)
│   ├── tools/               # pluggable real/mock investigation tools   (PR #3)
│   ├── agent.py             # Claude-driven reasoning loop              (PR #4)
│   ├── prompts.py           # system prompt + decision criteria         (PR #4)
│   └── main.py              # CLI entrypoint + report rendering         (PR #5)
├── alerts/                  # sample alert fixtures
└── reports/                 # generated investigation reports (gitignored)
```

## Roadmap

- [x] **PR #1** — Architecture document + project scaffold + data models + sample alerts
- [x] **PR #2** — AI-security guardrail layer (trust boundaries: ingress, indicator-safety/anti-SSRF, output sanitization, decision default-deny)
- [ ] **PR #3** — Pluggable tool layer (real adapters + mocks)
- [ ] **PR #4** — Claude-driven agent loop + decision logic
- [ ] **PR #5** — JSON + Markdown reporting + CLI + demo

---

*Built as the AI Investigation Agent home assignment.*
