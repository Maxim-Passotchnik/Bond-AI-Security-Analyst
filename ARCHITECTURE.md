# Bond — AI Security Analyst · Architecture

> An autonomous AI agent that investigates a security alert the way a Tier-1 SecOps
> analyst would: extract indicators, query threat-intel and OSINT tools, reason over
> the evidence, and reach a defensible verdict — **Auto-Close** or **Escalate** — with
> a structured, sourced report.

---

# Page 1 — Current System Design

## 1. Overview

Bond is triggered by a single security **alert** (JSON) and is responsible for one
contract:

> *Given an alert, autonomously gather enough context to either safely **close** it
> (false-positive / benign) or **escalate** it to a human with an actionable, evidence-backed report.*

The loop is powered by the **Claude API** using native **tool-use**: Claude decides
which indicators matter, which tools to call, and when it has seen enough to conclude.
Bond is model-driven in its *reasoning* but deterministic in its *control flow*,
state handling, and output schema — the parts that must be reliable in a SOC.

## 2. System Diagram

> 🛡️ = a **guardrail / trust boundary** (see §5). Untrusted data is sanitized at every
> point it enters the model's context, and the system always fails *safe* (toward escalation).

```mermaid
flowchart TD
    A[Security Alert<br/>JSON] --> G1{{🛡️ Ingress Guardrail<br/>schema · size · injection scan<br/>quarantine untrusted text}}
    G1 --> B[Alert Parser<br/>normalize → Alert]
    B --> C[IOC Extractor<br/>hashes, IPs, domains,<br/>users, hosts, URLs]
    C --> D[InvestigationState<br/>alert + IOCs + evidence ledger]

    subgraph LOOP [Agent Loop · Claude-driven]
        direction TB
        E[Reasoner<br/>Claude tool-use] -->|tool_use| G2{{🛡️ Indicator Safety<br/>block private/reserved IPs<br/>anti-SSRF · defang · rate cap}}
        G2 --> F[Tool Dispatcher]
        F -->|raw result| G3{{🛡️ Output Sanitization<br/>wrap as untrusted data}}
        G3 -->|tool_result| E
    end

    D --> E

    F --> T1[Hash / File reputation<br/>VirusTotal · MalwareBazaar]
    F --> T2[IP / Domain reputation<br/>AbuseIPDB · ThreatFox · OTX]
    F --> T3[WHOIS · DNS · GeoIP]
    F --> T4[Web / News search<br/>DuckDuckGo · Brave]
    T1 & T2 & T3 & T4 --> G3
    G3 -->|Evidence| D

    E -->|investigation_complete| G4{{🛡️ Decision Guardrail<br/>structured-only · asymmetric<br/>default-deny → ESCALATE}}
    G4 --> G[Decision Engine<br/>Auto-Close vs Escalate<br/>+ confidence]
    G --> H[Report Renderer]
    H --> J[(JSON report)]
    H --> K[(Markdown report)]
    G --> L{{Action:<br/>AUTO_CLOSE / ESCALATE}}
```

<details>
<summary>ASCII fallback (if Mermaid doesn't render)</summary>

```
 Alert(JSON) -> [GUARD: ingress] -> Alert Parser -> IOC Extractor -> State
                                                                       |
        +--------------------- Agent Loop ------------------+----------+
        | Reasoner (Claude) <-tool_result- [GUARD: output]  |  Tool    |
        |     |  -tool_use-> [GUARD: indicator safety] -->  | Dispatch |
        +-----|----------------------------------------|----+----------+
              |                                         v
              |                          [Hash rep][IP/Domain rep]
              |                          [WHOIS/DNS/Geo][Web search]
              |                                         | (-> GUARD: output)
              |                          Evidence appended to State
              v
   investigation_complete -> [GUARD: decision / default-deny] -> Decision Engine
                                          -> Report (JSON + MD)
                                          -> Action: AUTO_CLOSE | ESCALATE
```
</details>

## 3. Component Walkthrough

| Component | Responsibility |
|---|---|
| **Guardrail layer** 🛡️ | Cross-cutting trust-boundary enforcement (`src/guardrails.py`) invoked at ingress, before each tool call, on every tool result, and at the final decision. Detailed in §5. |
| **Alert Parser** | Validates and normalizes the raw alert into a typed `Alert` (id, type, severity, entities, raw payload preserved for the report). |
| **IOC Extractor** | Pulls indicators (file hashes, IPs, domains, URLs, hostnames, users) from the alert's structured entities into a de-duplicated `IOC` list — the agent's starting work-list. |
| **Agent Loop** | The Claude-driven reason→act cycle. Claude sees the alert + accumulated evidence each turn and either requests a tool or signals completion. |
| **Tool Dispatcher** | Maps Claude's `tool_use` blocks to Python tool functions, enforces JSON schemas, and returns `tool_result`. Each tool returns **real** data if its API key is present, else a realistic **mock** — so Bond always runs. |
| **Decision Engine** | Forced via a structured `investigation_complete` tool call: produces the action, confidence, findings summary, rationale, sources, and next steps. |
| **Report Renderer** | Serializes the final `InvestigationReport` to both JSON (machine) and Markdown (human). |

## 4. Agent Implementation

### 4.1 State management
A single typed `InvestigationState` object is the backbone (`src/models.py`). It holds
the normalized `Alert`, the de-duplicated `IOC` list, an **append-only evidence ledger**
(`Evidence` objects, each tagged with tool, query, disposition, source URL, a
`is_mock` flag, and a timestamp), and a `step` counter. The dispatcher appends evidence;
the reasoner reads it back on the next turn. Because state is plain dataclasses, the
*entire investigation is serializable* — critical for auditability, replay, and the
scaling story on page 2.

### 4.2 Reasoning
Claude drives the loop via **native tool-use**. A system prompt frames Bond as a
disciplined Tier-1 analyst with explicit, non-negotiable decision criteria:

- **Never Auto-Close** an alert without corroborating evidence that the indicators are benign.
- **When uncertain, Escalate** — a false negative (missed true threat) is far costlier than a false positive.
- **Cite every claim** to the tool/source that produced it.

Each turn Claude either emits a `tool_use` request (continue investigating) or calls the
terminal `investigation_complete` tool (conclude). The model decides *which* IOCs are
worth enriching and *when* the picture is complete — that's the "thinking like an analyst" part.

### 4.3 Tool execution
Tools are registered with strict JSON input schemas and exposed to Claude in the
`tools` parameter. The dispatcher:

1. Receives a `tool_use` block, validates inputs against the schema.
2. Routes to the tool's `run()` — which attempts the live API and **falls back to a mock** on missing key / error / rate-limit.
3. Wraps the result as `Evidence` (with `is_mock` flag + source) and as a `tool_result` block returned to Claude.

Tool failures are returned as structured errors, not exceptions, so the agent can adapt
(try another tool, or conclude with lower confidence) rather than crash.

### 4.4 Termination & fail-safe
The loop ends when Claude calls `investigation_complete`, **or** when the
`BOND_MAX_STEPS` budget is exhausted. Budget exhaustion forces an **Escalate** verdict
with `Low` confidence — Bond never silently closes an alert it couldn't finish investigating.

## 5. AI Security & Guardrails (Trust Boundaries)

An autonomous agent that ingests attacker-influenced data and then *voluntarily fetches
more of it* (WHOIS records, web pages, search snippets) is a prime target for **prompt
injection**. The adversary's goal here is asymmetric and specific: **flip an `ESCALATE`
into an `AUTO_CLOSE`** so a real attack is dismissed as benign. Bond therefore treats
every point where untrusted data enters the model's context as a **trust boundary** and
enforces a guardrail there — defense-in-depth that always fails *safe* (toward
escalation), never *open*.

| # | Guardrail | Boundary | What it enforces |
|---|---|---|---|
| 1 | **Ingress validation** | alert → loop | Strict schema + size caps; injection/heuristic scan of free-text fields; all alert text quarantined inside `<untrusted_data>` delimiters (spotlighting) so the model reads it as data, never instructions. |
| 2 | **Indicator safety / anti-SSRF** | before tool calls | Refuse active lookups against private / reserved / internal IPs and the cloud metadata endpoint (`169.254.169.254`); defang URLs; cap IOC count to bound cost and resource exhaustion. |
| 3 | **Tool-output sanitization** | tool result → loop | All tool output (especially fetched web / WHOIS content) re-enters context wrapped as untrusted data; optional injection detector on HTML/text before ingestion. |
| 4 | **Decision guardrail** | loop → verdict | Verdict only via the structured `investigation_complete` tool — no free-form close. **Asymmetric:** an `AUTO_CLOSE` requires ≥N independent benign signals plus an injection self-check. **Default-deny:** any tripped guardrail or budget exhaustion forces `ESCALATE`. |
| 5 | **Prompt hardening** | system prompt | Explicit data-vs-instruction separation; Bond is told to **report any embedded instructions it finds as a security finding**. |
| 6 | **Data minimization** | tool layer | Only the specific indicator (a hash, an IP) is sent to third-party APIs — never the raw alert or its PII. |

**Key principle — injection is a signal, not just noise.** A prompt-injection attempt
embedded in an alert or IOC is *itself evidence of malicious intent*. Bond does not
silently strip it; it records `"embedded instruction detected in <field>"` as a finding
that pushes the verdict toward **ESCALATE**. The guardrail doubles as a detector.

**Framework alignment.** These map to the **OWASP Top 10 for LLM Applications**:
LLM01 Prompt Injection (guardrails 1, 3, 5), LLM02 Insecure Output Handling (3),
LLM06 Sensitive Information Disclosure (6), and LLM08 Excessive Agency (2, 4).
Implemented as a dedicated `src/guardrails.py` invoked at each boundary above.

---

# Page 2 — Future Development & Vision

## 6. Scaling to hundreds of alerts/day

The single-process CLI is the seed of a horizontally-scalable service. Because each
investigation is **stateless given its alert** and the state is fully serializable, scaling
is largely a matter of queueing and fan-out.

```mermaid
flowchart LR
    SRC[EDR / SIEM / Mail GW] -->|webhook| ING[Ingestion API]
    ING --> Q[(Alert Queue<br/>SQS / Kafka)]
    Q --> W1[Agent Worker]
    Q --> W2[Agent Worker]
    Q --> W3[Agent Worker ...autoscaled]
    W1 & W2 & W3 --> CACHE[(IOC/TI Cache<br/>Redis)]
    W1 & W2 & W3 --> STORE[(Report Store<br/>+ audit DB)]
    W1 & W2 & W3 --> CLAUDE[Claude API<br/>prompt caching]
    STORE --> UI[Analyst Console / SOAR]
```

**Architecture & resource levers:**
- **Queue-based ingestion** decouples alert spikes from processing; workers pull at their own rate.
- **Stateless autoscaled workers** (containers on K8s/ECS) scale on queue depth. Each worker runs one investigation; horizontal scale = throughput.
- **Prompt caching** on the static system prompt + tool definitions cuts per-alert token cost and latency dramatically (the static prefix is identical across every alert).
- **Shared IOC/TI cache (Redis)** with TTLs: the same hash/IP recurs across alerts — cache reputation lookups so we don't re-query (and don't burn free-tier quotas).
- **Rate-limit & cost governance:** per-provider token buckets for free-tier APIs; a per-alert token/$ budget; a cheaper triage model (see §6) in front of the expensive loop.
- **Idempotency & dedup:** hash incoming alerts so duplicates/storms collapse to one investigation.

## 7. Roadmap — next stages of development

- **Richer tool set:** live SIEM/EDR queries (pull real host timeline, sibling alerts), sandbox detonation for unknown files, an identity/asset graph for blast-radius, ticketing/SOAR actions (isolate host, disable account).
- **Triage pre-filter:** a fast, cheap model classifies obvious noise before the full loop runs — reserving Claude's reasoning budget for genuinely ambiguous alerts.
- **Human-in-the-loop feedback:** capture every analyst override (Bond said Close, human Escalated) as labeled training/eval data — the flywheel that drives accuracy.
- **Correlation across alerts:** group related alerts into a single incident investigation instead of treating each in isolation.
- **Confidence calibration & guardrails:** require N independent malicious signals before high-confidence verdicts; add adversarial self-check on Auto-Close decisions.

## 8. Testing & accuracy strategy

The core risk in an auto-closing agent is **false negatives** (closing a real threat).
Testing is built to drive those toward zero while keeping false positives manageable.

- **Labeled alert corpus:** a growing fixture set of alerts with known ground-truth dispositions (TP/FP) spanning every alert type, including adversarial edge cases.
- **Regression harness:** run the full corpus through Bond on every change; measure **precision/recall on the Auto-Close decision** and track a **confusion matrix**. Gate merges on "zero new false negatives."
- **Deterministic tool mocks** make these runs reproducible and offline — the same alert yields the same evidence, so accuracy regressions are attributable to prompt/logic changes, not API flakiness.
- **LLM-as-judge** scores report quality (is the rationale sound? are claims sourced? is the summary faithful to the evidence?) separately from the binary decision.
- **Asymmetric thresholds:** Auto-Close requires a higher evidentiary bar than Escalate; we tune toward recall on the malicious class even at some precision cost.
- **Shadow mode before autonomy:** in production, run Bond alongside human analysts and compare verdicts before granting it authority to actually close alerts.
