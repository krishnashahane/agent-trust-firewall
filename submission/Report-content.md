# Agent Trust Firewall — Semester Integrated Project Report Content

Every section of the report format, in order. All figures are measured on the final build (22 November 2026). Blanks (`____`) are details only you can fill in.

---

## Certificate

This is to certify that the project report entitled **"Agent Trust Firewall: A Zero-Trust Security Gateway for AI Agents"** submitted by ____ (Roll No. ____) in partial fulfilment of the requirements of the Semester Integrated Project, Programme ____, Department of ____, ____ (Institution), during the Academic Year 2026–27 (Odd Semester), is a record of bona fide work carried out under my guidance and supervision.

Guide / Mentor: ____  Signature: ____  Date: ____
Head of Department: ____  Signature: ____  Date: ____

---

## Student Declaration

I/We hereby declare that the project report entitled **"Agent Trust Firewall: A Zero-Trust Security Gateway for AI Agents"** is an original work carried out by me/us under the guidance of ____, and has not been submitted elsewhere for the award of any degree or diploma. All sources used have been duly acknowledged in the references.

Name(s) and Roll No(s): ____  Signature(s): ____  Date: ____  Place: ____

---

## Acknowledgement

I/We express sincere gratitude to our guide/mentor ____ for continuous guidance and feedback throughout this project, and to the Head of Department ____ and the faculty of the Department of ____ for providing the resources and environment to carry out this work. We also thank the open-source communities behind Next.js, the noble cryptography libraries and the Model Context Protocol, whose work this project builds on.

---

## Abstract

AI agents increasingly act autonomously: they book meetings, send email, move money and run code by calling tools and APIs. When an agent is compromised through a leaked key or an injected prompt, its requests are indistinguishable from legitimate ones, because they carry valid credentials and target familiar endpoints. Existing controls do not close this gap. API keys and OAuth bearer tokens are replayable and do not prove who is calling at the moment of each request, and research on agent attacks measures the problem without providing an enforcement point.

This project presents the **Agent Trust Firewall (ATF)**, a zero-trust gateway that sits in front of every agent tool call and decides ALLOW, FLAG (hold for human review) or BLOCK before the call executes. Each call:
- is end-to-end encrypted (X25519, HKDF-SHA256, XChaCha20-Poly1305);
- carries a Schnorr proof of key possession bound to a single-use challenge and the exact request;
- proves its one required permission with a Merkle inclusion proof, so the gateway never holds an agent's full permission list;
- is scored by an explainable seven-signal risk engine with non-tunable hard rules and escalation floors.

Every decision is appended to a SHA-256 hash-chained audit log, and signed checkpoints let any third party detect even a full rewrite by the operator. The system also detects disguised prompt injection (encoding, look-alike characters, spacing tricks) and can proxy any existing Model Context Protocol server.

The system is implemented in TypeScript on Next.js with Neon Postgres and deployed on Vercel. Results:
- In evaluation, all 8 hostile scenarios were stopped (4 blocked, 4 flagged) and the legitimate call was allowed.
- Disguised-injection detection improved from 1 of 10 to 10 of 10 with no false alarms on ordinary text.
- 72 of 72 routine calls were allowed.
- The median decision time is 1.77 ms.
- The implementation passes 224 automated tests and 30 security invariants, with zero known dependency vulnerabilities.

**Keywords:** AI agent security, zero trust, prompt injection, Schnorr proof, Merkle tree, tamper-evident logging, Model Context Protocol.

---

## Table of Contents

- Certificate
- Student Declaration
- Acknowledgement
- Abstract
- List of Figures
- List of Tables
- 1. Introduction
  - 1.1 Background and real-world problem
  - 1.2 Problem statement
  - 1.3 Project objectives
  - 1.4 Scope and constraints
  - 1.5 Expected outcomes
- 2. Literature Review / Background Study
  - 2.1 Prior approaches and related work
  - 2.2 Comparison of existing solutions
  - 2.3 Research / practical gap
  - 2.4 References supporting problem selection
- 3. Subject-wise Integration
  - 3.1 Course concepts applied
  - 3.2 Skill–NOS–Project mapping
- 4. System Design and Methodology
  - 4.1 Requirements and specifications
  - 4.2 Architecture, workflow and flowchart
  - 4.3 Algorithms, models and design approach
  - 4.4 Tools, datasets, hardware and software
  - 4.5 Design decisions and justification
- 5. Implementation and Development
  - 5.1 Module-wise development
  - 5.2 Code, prototype and system details
  - 5.3 Versioning and implementation evidence
  - 5.4 Challenges and modifications
- 6. Testing, Results and Discussion
  - 6.1 Test plan, test cases and validation
  - 6.2 Results, tables, graphs and screenshots
  - 6.3 Comparison with objectives and baseline
  - 6.4 Limitations and interpretation
- 7. Conclusion and Future Scope
- 8. References

## List of Figures

- Fig. 1.1 — Existing system → problem → proposed system → expected improvement
- Fig. 4.1 — System architecture
- Fig. 4.2 — Decision workflow: Input → Pre-processing → Processing → Algorithm → Database → Output
- Fig. 4.3 — Development process flowchart
- Fig. 6.1 — Overview page with live interception (screenshot `01-overview.jpg`)
- Fig. 6.2 — Console: live traffic and risk over time (`02-console.jpg`)
- Fig. 6.3 — Attack range: capability escalation blocked (`03-attack-range.jpg`)
- Fig. 6.4 — Audit: forged record detected, fingerprint still matches (`04-audit.jpg`)
- Fig. 6.5 — Agents: trust, revoked key, proved capabilities (`05-agents.jpg`)
- Fig. 6.6 — Risk tuning preview at default settings (`06-tuning.jpg`)
- Fig. 6.7 — Graph: disguised injections caught, before vs after
- Fig. 6.8 — Graph: response time (p50 / p95)

## List of Tables

- Table 2.1 — Comparison of existing work (13 references)
- Table 3.1 — Course concepts applied
- Table 3.2 — Skill–NOS–Project mapping
- Table 4.1 — Functional requirements
- Table 4.2 — Non-functional requirements
- Table 4.3 — Risk signals and default weights
- Table 4.4 — Tools and technologies
- Table 5.1 — Modules and source files
- Table 5.2 — Version history
- Table 6.1 — Test suite summary
- Table 6.2 — Attack scenario results
- Table 6.3 — Disguised-injection detection
- Table 6.4 — Response time
- Table 6.5 — Precision and recall
- Table 6.6 — Objectives vs outcomes

---

## 1. Introduction

### 1.1 Background and real-world problem

AI agents are software systems built on large language models that take actions on their own: booking travel, sending messages, querying databases, executing code and making payments, by calling tools and APIs. Protocols such as the Model Context Protocol (MCP) make it easy to connect an agent to many tools.

This autonomy creates a new security problem. A compromised agent cannot be told apart from a healthy one. If an agent's API key leaks, or its instructions are hijacked through prompt injection (text hidden in a web page, email or document that the model reads), the malicious requests carry the same valid credentials and go to the same endpoints. OWASP ranks prompt injection as the top risk for LLM applications (LLM01).

Traditional API keys and OAuth bearer tokens prove only that someone once held a secret. A stolen token can be replayed, it says nothing about whether *this* request came from the intended agent, and it cannot express or check "this agent may book meetings but not charge cards" at the moment of each call. Meanwhile, logs recording what agents did can be altered by whoever controls them, which undermines incident investigation.

### 1.2 Problem statement

To design and develop a zero-trust security gateway system that addresses the problem of compromised or misbehaving AI agents acting through trusted credentials, by using per-request cryptographic identity proofs, least-privilege capability proofs, explainable multi-signal risk scoring and a tamper-evident audit log, and provides real-time allow / flag / block enforcement with a plain-language explanation for every decision.

### 1.3 Project objectives

1. Prove agent identity on every call without transmitting the secret key, and make a captured proof useless for any other call (replay protection).
2. Enforce least privilege: an agent may only invoke tools its granted capabilities cover, and the gateway should not need to hold the full grant list.
3. Score each call's risk with explainable signals (identity, context, behaviour, rate, payload, reputation, threat intel), where every point traces to a stated reason.
4. Make certain violations non-negotiable (hard rules) and ensure confident detections are never averaged away (escalation floors).
5. Keep a tamper-evident audit trail that detects edits, deletions, and even a full rewrite by the operator.
6. Detect disguised prompt injection and credential leakage in call arguments.
7. Protect existing tools without modifying them, including any MCP server.
8. Provide a console that non-specialists can understand, and deploy the system publicly.

### 1.4 Scope and constraints

**In scope**
- Agent-to-tool calls over HTTP and MCP
- Enrolment, identity proof, capability proof, risk scoring, policy and audit
- An operator console
- Durable storage and deployment

**Out of scope**
- Securing the language model's internal reasoning
- Agents that bypass the gateway
- Anonymous or privacy-preserving credentials
- Training a machine-learning classifier

**Constraints**
- The secret key must never leave the agent.
- Decisions must be fast enough for the request path.
- The system must run serverless, so state must be shareable across instances.
- Heuristic detections must not block outright, because they can produce false positives.
- The gateway must read the outer request to score it, so it is a trusted endpoint for that layer. Fields sealed to the destination remain unreadable to it.

### 1.5 Expected outcomes

- A working, deployed gateway that blocks impersonation, replay, revoked keys and privilege escalation, and holds suspicious-but-authorised behaviour for human review.
- An explanation in plain language for every verdict.
- An audit log whose integrity can be verified by anyone.
- A measurable improvement in detecting disguised prompt injection.
- A demonstrable attack range for evaluation and teaching.

---

## 2. Literature Review / Background Study

### 2.1 Prior approaches and related work

**Attack studies and benchmarks**
- Perez and Ribeiro [1] showed that short injected prompts reliably hijack a model's goal or leak its prompt.
- Greshake et al. [2] demonstrated indirect prompt injection, where instructions hidden in content the model retrieves take over real LLM-integrated applications.
- InjecAgent [3] and AgentDojo [4] benchmark tool-using agents against injection and show that agents are measurably vulnerable and that existing defences reduce, but do not eliminate, attack success.

**Guidance and architecture**
- The OWASP Top 10 for LLM Applications [5] lists prompt injection as LLM01 and recommends least privilege and human approval for high-risk actions.
- NIST SP 800-207 [6] defines Zero Trust Architecture: authenticate and authorise every request at a policy enforcement point instead of trusting network location.

**Authorisation standards**
- OAuth 2.0 [7] is the de facto standard for delegated, scoped API access. It uses bearer tokens, which are usable by anyone who obtains them.

**Cryptographic building blocks**
- Schnorr proofs [8], made non-interactive by the Fiat–Shamir heuristic [9], prove knowledge of a secret key efficiently.
- Merkle trees [10] authenticate any member of a set with a single root and a logarithmic-size proof.
- Secure audit logs [11], tamper-evident history trees [12] and Certificate Transparency [13] establish that hash-chained or Merkle-structured logs make tampering detectable, and that published signed heads prevent silent rewrites.

### 2.2 Comparison of existing solutions (Table 2.1)

| Author / Ref. No | Key idea | Method | Key finding | Limitation |
|---|---|---|---|---|
| [1] Perez & Ribeiro, 2022 | Prompt injection: goal hijacking and prompt leaking | Handcrafted adversarial prompts against GPT-3 (PromptInject) | Short injected text reliably overrides instructions | Studies the model only; no tool-call-layer defence |
| [2] Greshake et al., 2023 | Indirect prompt injection via retrieved content | Attacks on real LLM-integrated applications | Retrieved data can take over an application | Threat characterised; mitigations left open |
| [3] Zhan et al., 2024 (InjecAgent) | Injection benchmark for tool-using agents | User-tool / attacker-instruction test cases | Tool-integrated agents, including GPT-4-based ones, are measurably vulnerable | No runtime enforcement |
| [4] Debenedetti et al., 2024 (AgentDojo) | Dynamic environment for attacks and defences | Realistic tasks plus injection tasks | Defences lower but do not remove attack success | Evaluation framework, not a gateway |
| [5] OWASP, 2025 | LLM application risk ranking | Expert consensus | Prompt injection is LLM01; least privilege and human approval | No reference implementation |
| [6] NIST SP 800-207, 2020 | Zero Trust Architecture | Per-request policy decision and enforcement points | Authenticate and authorise each request | Designed for humans and devices, not agents |
| [7] RFC 6749, 2012 (OAuth 2.0) | Scoped delegated tokens | Bearer tokens | De facto API authorisation standard | Stolen tokens replayable; no per-call proof |
| [8] Schnorr, 1991; [9] Fiat & Shamir, 1987 | Proof of knowledge of a secret key | Sigma protocol made non-interactive by hashing | Compact and secure under discrete log | Proves possession only, not intent or risk |
| [10] Merkle, 1988 | One root authenticates a set | Hash tree with inclusion proofs | Members provable without revealing the others | Needs canonical encoding and domain separation |
| [11] Schneier & Kelsey, 1999 | Secure audit logs | Hash chains with evolving keys | Tampering with past entries detectable | Detection after the fact; trusted verifier |
| [12] Crosby & Wallach, 2009 | Tamper-evident history trees | Merkle history trees, consistency proofs | Efficient proof an old log is a prefix of the new | Auditors must keep commitments |
| [13] RFC 6962, 2013 (Certificate Transparency) | Public append-only logs | Merkle tree, signed tree heads, monitors | Operators cannot silently rewrite | Heavy infrastructure; for certificates |

### 2.3 Research / practical gap

Existing work either measures agent attacks [1]–[4], states principles [5], [6], authorises with replayable tokens [7], or provides isolated primitives [8]–[13]. No single enforcement point, placed in front of agent tool calls, combines all of:
- a per-call proof of identity that cannot be replayed;
- least-privilege authorisation that does not expose an agent's full permissions;
- explainable risk scoring that never averages away a confident detection;
- an audit trail resistant even to its operator.

The practical gap is integration at the point of action.

**How the project addresses the gap:** ATF routes every call, over HTTP or MCP, through one `decide()` function that applies all four protections, and anchors its audit log with signed checkpoints that outside parties can keep.

### 2.4 References supporting problem selection

- Prompt injection's prevalence and severity: [1], [2], [5]
- Agents' measurable vulnerability: [3], [4]
- The zero-trust enforcement model: [6]
- The weakness of bearer tokens: [7]
- The cryptographic foundations chosen: [8]–[10], [14]–[17]
- Tamper-evident logging: [11]–[13]
- Unicode spoofing (look-alike characters): [18]
- MCP as the agent–tool interface: [19]

---

## 3. Subject-wise Integration

### 3.1 Course concepts applied (Table 3.1)

| Course / subject area | Concept applied in the project |
|---|---|
| Cryptography & Network Security | Public-key cryptography (Ed25519, X25519); Schnorr proof of knowledge with the Fiat–Shamir transform; authenticated encryption (XChaCha20-Poly1305); key derivation (HKDF); hashing and domain separation (SHA-256); replay protection with nonces; zero trust; constant-time comparison |
| Data Structures & Algorithms | Merkle trees and inclusion proofs; hash chains; fixed-window rate limiting; bounded traversal of nested input; sorting and set operations for baselines |
| Database Management Systems | Relational schema design (agents, nonces, events, audit, rate windows); primary keys to prevent forked chains; atomic `DELETE … RETURNING` for single-use nonces; atomic upsert counters; indexing; idempotent migrations |
| Software Engineering | Requirements, modular architecture (ports and adapters for storage), version control, automated testing (unit, integration, end-to-end), design decision records, code review |
| Web Technologies | Next.js App Router, React components, REST API design, HTTP status semantics, Content Security Policy, security headers, same-origin checks |
| Operating Systems / Systems Programming | Child-process management and stdio pipes for the MCP proxy; JSON-RPC message framing; timeouts and process shutdown |
| Computer Networks | Client–server request/response, round-trip latency, IP address classification for SSRF protection (private, loopback, link-local, CGNAT ranges) |
| Artificial Intelligence | LLM agents, tool use, prompt injection threat model; rule-based anomaly detection with weighted signals |
| Probability & Statistics | Weighted scoring, thresholds, precision and recall, percentile latency (p50 / p95), Shannon entropy of payloads |
| Human–Computer Interaction | Plain-language explanations, accessible colour use (verdict colour always paired with a word), reduced-motion support |

### 3.2 Skill–NOS–Project mapping (Table 3.2)

NOS codes and titles depend on your programme's qualification pack. Fill them in from your syllabus.

| Skill | NOS code / title | Where it is applied in the project |
|---|---|---|
| Secure application development | ____ | Guard chain on every API route; strict CSP; input validation with Zod |
| Applied cryptography | ____ | Identity proofs, sealed envelopes, Merkle capabilities, signed checkpoints |
| Database design and administration | ____ | Postgres schema, atomic nonce consumption, shared rate limits |
| Software testing and quality assurance | ____ | 224 tests, 30 invariants, attack scenarios, smoke test |
| Web front-end development | ____ | 7-page Next.js/React console |
| Cloud deployment and operations | ____ | Vercel deployment, environment secrets, health checks |
| Threat analysis and security monitoring | ____ | Attack range, risk engine, threat-intel enrichment, audit |
| Technical documentation and communication | ____ | README, security model, design decision records, glossary |

---

## 4. System Design and Methodology

### 4.1 Requirements and specifications

**Functional requirements (Table 4.1)**

| ID | Requirement |
|---|---|
| FR1 | An operator enrols an agent with its public keys and a capability root; enrolment requires an admin token |
| FR2 | The gateway issues a single-use, agent-bound challenge that expires after 120 s |
| FR3 | The gateway accepts a sealed (encrypted) call, opens it and validates its structure |
| FR4 | The gateway verifies the agent's proof of key possession, bound to the challenge and the exact request |
| FR5 | The gateway verifies the Merkle proof of the capability the call uses, and that the capability covers the tool |
| FR6 | The gateway scores the call with 7 signals and returns ALLOW / FLAG / BLOCK with a reason |
| FR7 | Hard-rule violations always block; confident detections always flag |
| FR8 | Every decision is appended to a hash-chained audit log; anyone can verify the chain and save signed checkpoints |
| FR9 | The verdict is sealed back to the agent with its next challenge |
| FR10 | An MCP proxy forwards an allowed call to a real MCP server and holds or refuses all others |
| FR11 | The console shows traffic, agents, an attack range, the audit log, a tuning preview and a glossary |

**Non-functional requirements (Table 4.2)**

| Category | Requirement | Achieved |
|---|---|---|
| Performance | Decision well under 10 ms in-process | 1.77 ms median, 2.04 ms p95 |
| Security | No secret transmitted or stored; fail closed on any error | Asserted by `npm run verify` |
| Reliability | Works without a database; durable with one | Memory store / Postgres store |
| Scalability | Stateless serverless instances share state | Postgres-backed nonces, audit and rate limits |
| Usability | Understandable by non-engineers | Plain-language copy, glossary, verdict words |
| Maintainability | Modular, tested, documented | 91 source files, 224 tests, design records |
| Accessibility | WCAG-conscious UI | Colour paired with text; reduced-motion support |

### 4.2 Architecture, workflow and flowchart

**Architecture (Fig. 4.1)**

| Layer | Contents |
|---|---|
| Users | Operator (browser); AI agent (SDK); MCP client |
| Frontend / UI | Next.js + React console, 7 pages |
| Backend | 15 REST API routes, each passing origin check → rate limit → admin token (enrolment) → schema validation |
| Application logic (`src/lib/atf`) | identity, crypto, risk engine, policy, audit, threat intel, MCP proxy |
| Database | Neon Postgres: `atf_agents`, `atf_nonces`, `atf_events`, `atf_audit`, `atf_rate` |
| External | GreyNoise, Shodan InternetDB, AbuseIPDB, AlienVault OTX; the protected upstream tool or MCP server; Vercel hosting |

**Decision workflow (Fig. 4.2)**
Input (sealed call + challenge) → Pre-processing (open envelope, schema check, undo text disguises) → Processing (verify identity, spend nonce, verify capability, build context) → Algorithm (7 signals → weighted score → hard rules → escalation floors → verdict) → Database (append audit record and event) → Output (verdict, score, reason, next challenge).

**Development process (Fig. 4.3)**
Requirement analysis → Design → Development → Testing → Evaluation, iterated per feature, with each change committed and verified.

### 4.3 Algorithms, models and design approach

**1. Proof of key possession (Schnorr over Ed25519, Fiat–Shamir)**
- Agent: chooses random r, computes R = r·G, then c = H(P, R, nonce, requestDigest), then s = r + c·x.
- Gateway: accepts if s·G = R + c·P.
- Because c includes the nonce *and* the request digest, a proof is valid for exactly one call.
- Public keys are rejected at enrolment if they are not canonical prime-order points.

**2. Capability proof (Merkle tree)**
- Capabilities (e.g. `calendar:createEvent`) are sorted and hashed into a tree, with leaf and node hashes domain-separated.
- Only the root is enrolled.
- Each call reveals one capability plus its sibling path. The gateway recomputes the root, then checks that the capability covers the tool (`calendar:*` covers `calendar.createEvent`, not `payments.charge`).

**3. Sealed envelopes**
X25519 ephemeral key agreement → HKDF-SHA256 → XChaCha20-Poly1305, with the agent ID and request digest bound as associated data. Sensitive fields can be sealed to the destination so the gateway scores them by size and shape without reading them.

**4. Risk engine (Table 4.3)**

| Signal | Weight | What it measures |
|---|---|---|
| Identity posture | 0.30 | Proof verified, key age, rotation, revocation |
| Request context | 0.25 | Does the capability cover the tool; tool sensitivity (blast radius) |
| Behaviour baseline | 0.15 | New tool, never-contacted destination (higher for sensitive actions), unusual hour; learned only from allowed calls |
| Payload inspection | 0.15 | Prompt-injection patterns, secret formats, entropy, sealed-field mismatch, scanned across de-obfuscated views |
| Threat intelligence | 0.12 | Live reputation of the agent's IP from four providers; never blocks alone |
| Request rate | 0.10 | Sustained volume and bursts compared with the agent's earlier pace |
| Reputation | 0.05 | The agent's recent verdict history |

- Score = Σ(weightᵢ × readingᵢ × 100) / Σweights, giving a value from 0 to 100.
- Flag at ≥ 45; block at ≥ 70.
- **Hard rules** (always BLOCK): unknown agent, revoked key, identity unproven, replayed challenge, capability unproven, capability escalation.
- **Escalation floors** (always at least FLAG): payload ≥ 0.75, rate ≥ 0.75, behaviour ≥ 0.6.

**5. Text de-obfuscation**
Each argument is scanned in several views, tried from least to most transformed:
1. The original text
2. URL-decoded and base64-decoded segments (up to 8, one level)
3. NFKC-folded text with invisible characters removed and Cyrillic/Greek look-alikes mapped
4. Punctuation between letters turned into spaces
5. Spaced-out single letters rejoined
6. Number-for-letter substitutions undone

**6. Audit chain and checkpoints**
- Each record stores the SHA-256 hash of its contents and the previous record's hash; `verifyChain` names the first broken record.
- A checkpoint is the head's sequence number and hash, signed with Ed25519.
- `checkConsistency` reports **consistent**, **rewritten** (including a log now shorter than the checkpoint), **broken**, or **unavailable**.

**7. Rate limiting**
A fixed window per client and route. With Postgres configured, each request is one atomic upsert, so all instances share one budget. If the database fails, each instance falls back to its own count.

### 4.4 Tools, datasets, hardware and software (Table 4.4)

| Category | Items |
|---|---|
| Languages | TypeScript 5.9, JavaScript, SQL, CSS |
| Frameworks | Next.js 16.4.6, React 19.3.1, Tailwind CSS 4.3.5 |
| Cryptography | @noble/curves 1.9.2, @noble/hashes 1.8.0, @noble/ciphers 1.3.0 |
| Validation | Zod 4.6.7 |
| Database | Neon serverless Postgres (@neondatabase/serverless 1.2.1) |
| Testing | Vitest 4.1.12, ESLint 9, custom invariant and smoke scripts |
| Hosting | Vercel (serverless Node.js), region bom1 |
| Runtime | Node.js 22.6+ (developed on Node 26) |
| Version control | Git, GitHub |
| Hardware | Developer laptop (macOS); no special hardware needed |
| Data | Synthetic demo fleet of 6 agents with real keys, proofs and public IP addresses; live threat-intel data from GreyNoise, Shodan InternetDB, AbuseIPDB and AlienVault OTX. No training dataset is used: the detectors are rule-based. |

### 4.5 Design decisions and justification

1. **Schnorr proof instead of a zkSNARK.** It provides the needed property (proving key possession without sending the key, bound to one request) with no trusted setup, millisecond cost and small audited libraries. It is, equivalently, a Schnorr signature. Anonymity was not a goal, because the risk engine must know which agent is calling.
2. **Hard rules and escalation floors outside the score.** A security rule that a slider can switch off is not a rule. During testing, a textbook prompt injection scored about 20/100 and was allowed until escalation floors were added.
3. **Merkle root at enrolment.** The gateway learns one capability per call and never stores the full grant list.
4. **Fail closed.** Any error in the decision path results in BLOCK with a stated reason.
5. **Audit stores digests, not payloads.** A log that leaks what it records is a liability.
6. **Signed checkpoints.** A hash chain alone cannot stop someone with database access from rewriting everything; a checkpoint held by someone else can.
7. **Heuristics flag rather than block.** Pattern detection can produce false positives, so a person should review those calls.
8. **Storage behind an interface.** The same engine runs on in-memory storage (zero configuration) or Postgres (durable, multi-instance).
9. **Per-visitor tuning sandboxes.** Configuration changes in the console never alter other visitors' scoring.

---

## 5. Implementation and Development

### 5.1 Module-wise development (Table 5.1)

| Module | Files | Purpose |
|---|---|---|
| Identity | `identity/schnorr.ts`, `nonce.ts`, `registry.ts`, `merkle.ts` | Proofs, single-use challenges, enrolment, capability trees |
| Admin | `admin.ts` | Constant-time admin-token check; enrolment disabled when no token is set |
| Crypto | `crypto/e2ee.ts`, `sealed.ts`, `primitives.ts` | Sealed envelopes and fields; hashing helpers |
| Risk | `risk/engine.ts`, `config.ts`, `preview.ts`, `signals/*.ts` (7 signals + `deobfuscate.ts`) | Scoring, configuration, tuning preview |
| Policy / interceptor | `interceptor/decide.ts`, `policy.ts`, `arguments.ts` | The decision path, hard rules, escalation |
| Audit | `audit/chain.ts`, `checkpoint.ts` | Hash chain, windowed verification, consistency, signed checkpoints |
| Storage | `store/port.ts`, `memory.ts`, `postgres.ts` | Storage interface and two implementations |
| Threat intel | `osint/*.ts` | Four providers, caching, SSRF-safe address checks |
| MCP | `mcp/server.ts`, `upstream.ts` | MCP server with demo tools or a proxy to a real upstream |
| SDK | `client.ts` | Agent-side signing and sealing |
| Web | `src/app/**` (7 pages, 15 API routes), `src/components/**` | Console and APIs |
| Guard | `src/lib/guard.ts`, `src/proxy.ts` | Origin, rate limit, admin, body validation, security headers |

### 5.2 Code, prototype and system details

- **Codebase:** about 15,500 lines across source, scripts and tests; 91 TypeScript source files.
- **API routes (15):** `/api/health`, `/api/agents`, `/api/agents/register`, `/api/agents/challenge`, `/api/gateway/pubkey`, `/api/gateway/intercept`, `/api/traffic`, `/api/audit`, `/api/audit/verify`, `/api/audit/checkpoint`, `/api/config`, `/api/config/preview`, `/api/simulate`, `/api/sealed-demo`, `/api/osint`.
- **Live prototype:** https://agentwall-pbl.vercel.app (Postgres storage, admin-protected enrolment).
- **Commands:**
  - `npm run dev` — run locally
  - `npm test` — 224 tests
  - `npm run verify` — 30 invariants
  - `npm run smoke` — end-to-end agent test
  - `npm run mcp` — MCP server / proxy

### 5.3 Versioning and implementation evidence (Table 5.2)

Git history (branch `main`, repository github.com/krishnashahane/agent-trust-firewall):

| Date | Commit |
|---|---|
| 2026-09-01 | fix: eliminate 503s and unauthenticated global state mutation |
| 2026-09-01 | feat: credibility metadata, footer, and honest data labelling |
| 2026-09-01 | fix: WCAG failures, click-stealing tap targets, and add real trend data |
| 2026-09-01 | docs: record the sandboxing model and non-blocking intel |
| 2026-09-02 | feat: durable Postgres storage behind the existing store port |
| 2026-09-02 | docs: setup instructions for durable storage in the README |
| 2026-09-02 | feat: interaction and motion layer |
| 2026-10-10 | fix: patch vulnerable dependencies, remove dead code, correct docs |
| 2026-11-22 | chore: patch Next.js, zod and vitest advisories and resync the lockfile |
| 2026-11-22 | fix(dev): let React's dev build run under the strict CSP |
| 2026-11-22 | refactor(ui): tighten the overview and stop overstating persistence |
| 2026-11-22 | fix(identity): enrol a capability root, never the capability list |
| 2026-11-22 | fix(security): require an operator token to enrol agents |
| 2026-11-22 | docs: call the identity proof what it is |
| 2026-11-22 | feat(audit): signed checkpoints that catch an operator rewriting history |
| 2026-11-22 | perf(gateway): return the next challenge with each verified verdict |
| 2026-11-22 | fix(payload): see through the disguises that beat plain regexes |
| 2026-11-22 | fix(guard): share rate limits across instances when a database is set |
| 2026-11-22 | feat(mcp): proxy a real MCP server through the firewall |
| 2026-11-22 | fix(payload): report a plainly written attack as plain |
| 2026-11-22 | feat(ui): explain the product to people who are not engineers |
| 2026-11-22 | docs: update test and invariant counts |
| 2026-11-22 | fix(risk): stop a rate flood and a first-contact export from being allowed |
| 2026-11-22 | fix(tuning): make the preview honest about escalations and weights |

Each commit message records the problem, the change and its verification. Design decision records are in `docs/decisions/`.

### 5.4 Challenges and modifications

1. **Lost local copy.** The project folder on an iCloud-synced Desktop was emptied of source files. It was recovered from the GitHub repository.
2. **Dependency vulnerabilities.** Next.js had critical advisories and zod a memory-exhaustion bug, and the lockfile was out of sync, so clean installs failed. Dependencies were upgraded within their major versions and `npm audit` now reports zero vulnerabilities.
3. **Open enrolment.** Anyone could enrol an agent with any capability. An admin token was added, and enrolment is disabled when no token is set.
4. **Overstated privacy claim.** Enrolment stored the full capability list. It now takes only the Merkle root.
5. **Overstated "zero-knowledge" wording.** The proof was relabelled accurately as a proof of key possession (a Schnorr signature), and the design record was corrected.
6. **Audit log could be fully rewritten by its operator.** Signed checkpoints and a consistency check were added. A latent bug where logs over 2,000 records would be reported as broken was also fixed.
7. **Two round trips per call.** The verdict now returns the next challenge, cutting mean latency by about 21%.
8. **Disguised injections evaded detection** (1 of 10 caught). De-obfuscation views were added, and now 10 of 10 are caught with no false alarms.
9. **Per-instance rate limits.** Limits are now shared across instances through Postgres.
10. **MCP fronted only demo tools.** A real upstream proxy was added, and flagged calls are held.
11. **Rate flood and first-contact export were allowed.** Found by end-to-end measurement. Burst detection now compares against the agent's earlier pace, the behaviour baseline learns only from allowed calls, and escalation floors were added.
12. **Tuning preview was misleading.** It ignored escalations and weights. Events now record their signal readings, and the preview reproduces every verdict at the current settings.
13. **Jargon-heavy interface.** Plain-language copy and an "In plain terms" explainer were added for non-technical users.

---

## 6. Testing, Results and Discussion

### 6.1 Test plan, test cases and validation

**Test levels**
1. **Unit tests:** cryptography, Merkle proofs, every risk signal, the engine, policy, guards.
2. **Integration tests:** the full decision path, storage, audit chain, MCP with a real child-process upstream server.
3. **Scenario tests:** 9 attack scenarios through the real engine.
4. **Invariant checks:** 30 security properties asserted outside the test runner (`npm run verify`).
5. **End-to-end smoke test:** a real agent against a running server (`npm run smoke`).
6. **Live deployment checks:** pages, health, auth, flood verdict, checkpoint consistency on production.
7. **Manual UI testing** in a browser.

**Table 6.1 — Test suite summary**

| Suite | Count | Result |
|---|---|---|
| Automated tests (9 files: crypto, risk, interceptor, audit, MCP, guards, scenarios, session, OSINT) | 224 | All pass |
| Security invariants | 30 | All hold |
| End-to-end smoke checks | 9 | All pass |
| Type check, lint | — | Clean |
| Dependency audit | — | 0 vulnerabilities |

**Sample test cases**
- An unenrolled agent is blocked.
- A replayed proof is blocked.
- A proof moved to a different request is blocked.
- A revoked key is blocked at any configuration.
- A capability not held cannot be proved.
- An escalation is blocked.
- An envelope does not contain its plaintext.
- The gateway cannot open a destination-sealed field.
- Altering, re-hashing or deleting an audit record is detected.
- A full rewrite with recomputed hashes is caught by a saved checkpoint.
- An edited checkpoint fails signature verification.
- Argument values never reach the audit log.
- No secret key is stored.
- Cloud-metadata and private IP addresses are refused for threat lookups.
- Enrolment without the admin token is refused.
- Each of 9 disguised injections is caught, and 9 ordinary texts are not flagged.
- A blocked MCP call never reaches the upstream server.

### 6.2 Results, tables, graphs and screenshots

**Table 6.2 — Attack scenarios** (verdicts and scores from the final build)

| Scenario | Verdict | Score | Stopped by |
|---|---|---|---|
| A legitimate call | ALLOW | 3.2 | — |
| Agent nobody enrolled | BLOCK | 47.0 | unknown-agent |
| Replayed proof | BLOCK | 4.8 | replayed-challenge |
| Capability escalation | BLOCK | 35.9 | capability-escalation |
| Revoked key still in use | BLOCK | 36.3 | revoked-key |
| Rate flood (41 calls in 10 s) | FLAG | 11.7 | rate escalation |
| Full export to a never-seen host | FLAG | 13.6 | behaviour escalation |
| Prompt injection in arguments | FLAG | 16.9 | payload escalation |
| Secret riding out in a payload | FLAG | 25.5 | payload escalation |

**Table 6.3 — Disguised-injection detection**

| Disguise | Before | After |
|---|---|---|
| Plain text | Caught | Caught |
| Zero-width characters | Missed | Caught |
| Cyrillic look-alike letter | Missed | Caught |
| Full-width letters | Missed | Caught |
| Numbers for letters (1gn0r3) | Missed | Caught |
| Spaced-out letters | Missed | Caught |
| Punctuation between words | Missed | Caught |
| Base64-encoded | Missed | Caught |
| URL-encoded | Missed | Caught |
| Paraphrase ("forget everything you were told…") | Missed | Caught |
| **Total** | **1 / 10** | **10 / 10** |

Ordinary texts flagged: 0 of 9. A base64-encoded AWS key is also detected. A 32 KB hostile payload is scanned in under 5 ms.

**Table 6.4 — Response time (ms)**

| Measurement | p50 | p95 | Mean | n |
|---|---|---|---|---|
| Engine decision (in-process) | 1.77 | 2.04 | 1.83 | 500 |
| Sealed call over HTTP, 2 round trips | 14.34 | 36.44 | 15.34 | 20 |
| Sealed call over HTTP, 1 round trip | 11.88 | 15.19 | 12.09 | 20 |

**Table 6.5 — Precision and recall**

| Evaluation set | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| Attack scenarios | 8 | 0 | 0 | 1 | 1.00 | 1.00 |
| Injection detector | 10 | 0 | 0 | 9 | 1.00 | 1.00 |
| Routine seeded traffic (72 calls) | — | 0 | — | 72 | — | — |

**Graphs:** Fig. 6.7 (bar chart, before 1 vs after 10) and Fig. 6.8 (clustered bars, p50 and p95 for the three rows of Table 6.4).

**Screenshots:** Figs. 6.1–6.6, files in `submission/screens/`.

**Live system:** all 7 pages return HTTP 200; the audit chain is valid across 400+ Postgres records; enrolment without a token returns 401; a fresh checkpoint is consistent.

### 6.3 Comparison with objectives and baseline (Table 6.6)

| Objective | Baseline (static API key / initial version) | Outcome |
|---|---|---|
| Per-call identity, replay-proof | A stolen key works indefinitely | Replay and impersonation blocked by hard rules |
| Least privilege | Keys carry full access; enrolment stored the full list | Capability proof per call; only the root stored |
| Explainable risk | No scoring | 7 signals, each point explained |
| Confident detections never silenced | Flood and first-contact export were allowed | All 8 hostile scenarios stopped |
| Tamper-evident audit | Chain detected edits but not a full operator rewrite | Signed checkpoints detect full rewrites and truncation |
| Disguised injection | 1 / 10 | 10 / 10, 0 false alarms |
| Protect existing tools | Demo tools only | Proxy for any MCP server |
| Performance | — | 1.77 ms median decision |
| Usable by non-engineers | Jargon-heavy | Plain-language interface and glossary |

### 6.4 Limitations and interpretation

- The evaluation sets are small and hand-built. Precision and recall of 1.00 mean no errors on these sets, not on all real-world attacks.
- Payload detection is rule-based. Novel phrasings may still evade it, which is why it flags rather than blocks.
- The gateway reads the outer request in order to score it, so it is a trusted endpoint for that layer. Only destination-sealed fields stay hidden from it.
- Agents that do not route through the gateway are not protected.
- Checkpoints protect only if someone saves them outside the operator's control. Automated external publication is future work.
- Threat intelligence on shared cloud IP addresses is weak evidence. It is weighted lightly and never blocks alone.
- The demo agents are synthetic. Their cryptography, verdicts and addresses are real, but traffic patterns are simulated.
- HTTP latency was measured on localhost and excludes internet latency.

---

## 7. Conclusion and Future Scope

**Conclusion**
The Agent Trust Firewall shows that the gap between agent-attack research and practical enforcement can be closed with one gateway that every agent call must pass. By combining a per-call proof of key possession, least-privilege Merkle capability proofs, an explainable seven-signal risk engine with non-tunable hard rules and escalation floors, and a hash-chained audit log anchored by signed checkpoints, ATF stops impersonation, replay, revoked keys and privilege escalation outright, and holds floods, first-contact exports, prompt injection and leaked secrets for human review.

On the final build:
- all 8 hostile scenarios are stopped and all 72 routine calls are allowed;
- disguised-injection detection rose from 1 to 10 out of 10;
- decisions take under 2 ms;
- the system passes 224 tests and 30 security invariants;
- it runs publicly on Vercel with durable Postgres storage.

**Future scope**
1. Automatically publish checkpoints to an external transparency log, or to multiple independent witnesses.
2. Pilot ATF in front of real agent frameworks and popular MCP servers; publish an SDK package.
3. Load testing and horizontal scaling studies; multi-region deployment.
4. An ML-assisted payload classifier alongside the rule-based detector, evaluated on InjecAgent and AgentDojo.
5. The full Unicode confusables table (UTS #39) and additional encodings.
6. Human-review workflow for FLAG verdicts (approve or deny with audit).
7. Key-rotation and revocation APIs with multi-admin approval.
8. Policy-as-code for per-tool rules and time-of-day limits.

---

## 8. References

1. F. Perez and I. Ribeiro, "Ignore Previous Prompt: Attack Techniques for Language Models," NeurIPS ML Safety Workshop, 2022.
2. K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz and M. Fritz, "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," in Proc. ACM Workshop on Artificial Intelligence and Security (AISec), 2023.
3. Q. Zhan, Z. Liang, Z. Ying and D. Kang, "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents," in Findings of ACL, 2024.
4. E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer and F. Tramèr, "AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents," NeurIPS Datasets and Benchmarks Track, 2024.
5. OWASP Foundation, "OWASP Top 10 for Large Language Model Applications," 2025.
6. S. Rose, O. Borchert, S. Mitchell and S. Connelly, "Zero Trust Architecture," NIST Special Publication 800-207, 2020.
7. D. Hardt, Ed., "The OAuth 2.0 Authorization Framework," IETF RFC 6749, 2012.
8. C. P. Schnorr, "Efficient Signature Generation by Smart Cards," Journal of Cryptology, vol. 4, no. 3, pp. 161–174, 1991.
9. A. Fiat and A. Shamir, "How to Prove Yourself: Practical Solutions to Identification and Signature Problems," in Advances in Cryptology — CRYPTO '86, LNCS 263, 1987.
10. R. C. Merkle, "A Digital Signature Based on a Conventional Encryption Function," in Advances in Cryptology — CRYPTO '87, LNCS 293, 1988.
11. B. Schneier and J. Kelsey, "Secure Audit Logs to Support Computer Forensics," ACM Transactions on Information and System Security, vol. 2, no. 2, pp. 159–176, 1999.
12. S. A. Crosby and D. S. Wallach, "Efficient Data Structures for Tamper-Evident Logging," in Proc. 18th USENIX Security Symposium, 2009.
13. B. Laurie, A. Langley and E. Kasper, "Certificate Transparency," IETF RFC 6962, 2013.
14. D. J. Bernstein, N. Duif, T. Lange, P. Schwabe and B.-Y. Yang, "High-speed high-security signatures," Journal of Cryptographic Engineering, vol. 2, no. 2, pp. 77–89, 2012.
15. D. J. Bernstein, "Curve25519: New Diffie-Hellman Speed Records," in Public Key Cryptography — PKC 2006, LNCS 3958, 2006.
16. H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," IETF RFC 5869, 2010.
17. Y. Nir and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols," IETF RFC 8439, 2018.
18. Unicode Consortium, "Unicode Security Mechanisms," Unicode Technical Standard #39.
19. Model Context Protocol, "Specification, version 2025-06-18," modelcontextprotocol.io.
20. Vercel, "Next.js Documentation," nextjs.org/docs.
21. P. Miller, "noble-curves, noble-hashes and noble-ciphers," github.com/paulmillr.
22. Neon, "Neon Serverless Postgres Documentation," neon.tech/docs.
23. Data sources: GreyNoise Community API; Shodan InternetDB (internetdb.shodan.io); AbuseIPDB API v2; AlienVault OTX DirectConnect API.
