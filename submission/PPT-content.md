# Agent Trust Firewall — Presentation Content

Content for every slide in the review template, in order. All figures are measured on the final build (22 Nov 2026). Blanks (`____`) are details only you can fill in.

---

## Slide 1 — Title

- **Academic Year:** 2026–27 (Odd Semester)
- **Project Title:** Agent Trust Firewall (ATF): A Zero-Trust Security Gateway for AI Agents
- **Team Members:** ____
- **Programme / Class:** ____
- **Guide / Mentor:** ____
- **Live system:** https://agentwall-pbl.vercel.app
- **Source code:** github.com/krishnashahane/agent-trust-firewall

---

## Slide 2 — Presentation Roadmap

1. Introduction
2. Literature Survey
3. Problem Statement
4. Solution Proposed
5. Approach & Methodology
6. System Architecture
7. Demonstration of Modules
8. Results
9. Conclusion
10. References

---

## Slide 3 — 1. Introduction

**Context (1–2 sentences)**
AI agents now book meetings, send email, move money and run code on their own by calling tools and APIs. When an agent is compromised by a leaked key or a poisoned prompt, its requests look exactly like a healthy agent's: same credentials, same endpoints, no alarm.

**Why this matters now**
- Agents act without a human approving each call.
- Prompt injection is ranked the #1 risk for LLM applications (OWASP LLM01).
- The Model Context Protocol (MCP) is becoming the standard way agents reach tools, which creates one natural place to enforce security.
- An API key proves someone once had a secret. It does not prove that *this* request, right now, came from the agent you approved.

**Who benefits**
- **Companies deploying agents:** a hijacked agent is stopped before it acts.
- **Security and compliance teams:** every decision is explained and kept in a tamper-evident audit trail.
- **API and tool providers:** only verified, authorised calls reach them.
- **End users:** a compromised agent cannot move their data or money.

**Plain-language analogy (for non-technical listeners)**
Airport security for AI agents. Every request is stopped at the gate and checked four ways:
1. **Checks the ID:** the agent proves it holds its secret key.
2. **Checks the ticket:** the agent is allowed to do this specific job.
3. **Scans the bag:** the request is scored for warning signs.
4. **Keeps a sealed logbook:** a record no one can quietly edit.

The result is one of three words: **Allowed**, **Flagged** (held for a person to review) or **Blocked**.

---

## Slide 4 — 2. Literature Survey: existing approaches

| Group | Works | Strength | Limitation |
|---|---|---|---|
| Attack studies & benchmarks | [1] Perez & Ribeiro; [2] Greshake et al.; [3] InjecAgent; [4] AgentDojo | Precisely characterise prompt-injection attacks on LLM agents | Measure the problem; no runtime enforcement point in front of tool calls |
| Guidance & architecture | [5] OWASP LLM Top 10; [6] NIST SP 800-207 Zero Trust | Least privilege, verify every request, human approval for risky actions | Principles only; written for human and device users, not autonomous agents |
| Authorisation standards | [7] OAuth 2.0 | Mature, scoped, widely deployed delegated access | Bearer tokens are replayable if stolen; no per-request proof of who is calling |
| Cryptographic building blocks | [8] Schnorr; [9] Fiat–Shamir; [10] Merkle; [11] Schneier & Kelsey; [12] Crosby & Wallach; [13] Certificate Transparency | Proofs of key possession, compact membership proofs, tamper-evident logs | Primitives, not a product: nothing combines them into one agent gateway |

---

## Slides 5–7 — 2. Literature Survey: comparison table (12 rows, 13 references)

| Author / Ref. No | Key idea | Method | Key finding | Limitation |
|---|---|---|---|---|
| [1] Perez & Ribeiro, 2022 | Prompt injection: goal hijacking and prompt leaking | Handcrafted adversarial prompts against GPT-3 (PromptInject framework) | Short injected text reliably overrides a model's instructions | Studies the model only; no defence at the tool-call layer |
| [2] Greshake et al., 2023 | Indirect prompt injection through content the model reads | Attacks demonstrated on real LLM-integrated applications | Retrieved data can carry instructions that take over an application | Characterises the threat; mitigations left open |
| [3] Zhan et al., 2024 (InjecAgent) | Benchmark for indirect injection on tool-using agents | Test cases pairing user tools with attacker instructions | Tool-integrated agents, including GPT-4-based ones, are measurably vulnerable | Measures attacks; provides no runtime enforcement |
| [4] Debenedetti et al., 2024 (AgentDojo) | Dynamic environment for agent attacks and defences | Realistic agent tasks combined with injection tasks | Existing defences lower attack success but do not remove it | An evaluation framework, not a deployable gateway |
| [5] OWASP, 2025 (LLM Top 10) | Industry risk ranking for LLM applications | Expert community consensus | Prompt injection is LLM01; recommends least privilege and human approval | Guidance without a reference implementation |
| [6] Rose et al., NIST SP 800-207, 2020 | Zero Trust Architecture | Policy decision and enforcement points for every request | Never trust network location; authenticate and authorise each request | Designed for human and device users, not agents |
| [7] Hardt, RFC 6749, 2012 (OAuth 2.0) | Delegated, scoped access tokens | Bearer tokens issued per client and scope | De facto standard for API authorisation | A stolen bearer token can be replayed; no per-call proof |
| [8] Schnorr, 1991; [9] Fiat & Shamir, 1987 | Efficient proof of knowledge of a secret key | Sigma protocol made non-interactive by hashing | Compact, fast, secure under the discrete-log assumption | Proves key possession only, not intent or risk |
| [10] Merkle, 1988 | One root authenticates a whole set | Binary hash tree with logarithmic inclusion proofs | Any member is provable without revealing the others | Needs canonical encoding and domain separation |
| [11] Schneier & Kelsey, 1999 | Secure audit logs | Hash chains with evolving keys | Tampering with past entries becomes detectable | Detects after the fact; relies on a trusted verifier |
| [12] Crosby & Wallach, 2009 | Tamper-evident logging with history trees | Merkle history trees with consistency proofs | Efficient proof that an old log is a prefix of the new one | Auditors must retain and compare commitments |
| [13] Laurie et al., RFC 6962, 2013 | Certificate Transparency: public append-only logs | Merkle tree with signed tree heads and monitors | Log operators cannot silently rewrite history | Heavy infrastructure, built for certificates |

---

## Slide 8 — 2. Research / Problem Gap, and how the project addresses it

**The gap**
- Research measures agent attacks but offers no enforcement point.
- Guidance (OWASP, NIST) states principles without a mechanism.
- OAuth tokens are replayable and do not prove the caller on each request.
- The cryptographic primitives exist but have not been combined for agents.
- No single gateway proves identity, checks least privilege, scores risk and keeps a tamper-evident record for every agent tool call.

**How ATF addresses it**
- **One enforcement point:** every call passes the same `decide()` path, over HTTP or MCP.
- **Per-call proof:** a Schnorr proof bound to a single-use challenge and the exact request [8], [9].
- **Least privilege:** a Merkle proof of the one capability the call needs [10].
- **Explained risk:** 7 signals, hard rules and escalation floors, following OWASP and NIST guidance [5], [6].
- **Rewrite-proof audit:** a hash chain plus signed checkpoints [11]–[13].

---

## Slide 9 — 3. Problem Statement

**Statement (recommended format)**
"To design and develop a zero-trust security gateway system that addresses the problem of compromised or misbehaving AI agents acting through trusted credentials, by using per-request cryptographic identity proofs, least-privilege capability proofs, explainable multi-signal risk scoring and a tamper-evident audit log, and provides real-time allow / flag / block enforcement with a plain-language explanation for every decision."

**The exact problem (one paragraph)**
A hijacked AI agent holds valid credentials and calls its usual endpoints. At the moment of the call, nothing proves which agent is asking, whether it may perform this specific action, or whether the request is a replay of an earlier one. The log of what happened can be rewritten by whoever controls it.

**Scope: in**
- Agent-to-tool calls over HTTP and MCP
- Identity, authorisation, risk scoring and audit
- An operator console for monitoring and tuning

**Scope: out**
- Securing the language model itself
- Agents that bypass the gateway
- Anonymous or privacy-preserving credentials
- Training a machine-learning detection model

**Why it is non-trivial (challenges and constraints)**
- The secret key must never be sent, yet must be proven on every call.
- A captured proof must not work twice, or on a different request.
- Attackers disguise malicious text (base64, look-alike letters, invisible characters) to evade checks.
- Weak warning signs must not be averaged into silence by a weighted score.
- The audit log must resist even its own operator.
- Decisions must be fast enough to sit in front of every call.

---

## Slide 10 — 4. Solution Proposed

**Diagram: Existing System → Problem → Proposed System → Expected Improvement**
1. **Existing system:** agents call APIs with static API keys or OAuth bearer tokens.
2. **Problem:** a stolen key or poisoned prompt looks like a healthy agent, and no record can be trusted.
3. **Proposed system:** the ATF gateway proves, authorises, scores and audits every call before it runs.
4. **Expected improvement:** hijacked or replayed calls are stopped, and every decision is explained and verifiable.

**Proposed system**
A gateway that sits between an AI agent and the tools or APIs it calls. Every call must clear four checks:
1. **Sealed in transit:** the agent encrypts the call with a fresh key each time.
2. **Identity, proved not claimed:** the agent proves it holds its secret key without sending it.
3. **Authority, minimally disclosed:** the agent proves the one permission this call needs.
4. **Risk, scored and explained:** seven signals produce a 0–100 score, every point traceable to a plain-language reason.

Outcome: **ALLOW**, **FLAG** (hold for a human) or **BLOCK**, and every decision is written to a hash-chained audit log.

**Major technologies**
- Next.js 16, React 19, TypeScript, Tailwind CSS
- Audited cryptography libraries: @noble/curves, @noble/hashes, @noble/ciphers
- Ed25519 (identity), X25519 + HKDF-SHA256 + XChaCha20-Poly1305 (encryption), SHA-256 (hashing)
- Neon serverless Postgres; Zod for input validation
- Vercel hosting; Vitest for testing
- Model Context Protocol (JSON-RPC 2.0 over stdio)

**Major features**
- End-to-end encrypted (sealed) agent calls, with sensitive fields sealed to the destination so the firewall cannot read them
- Proof of key possession bound to one single-use challenge and one request
- Merkle-tree capability proofs: the firewall stores only a fingerprint (root) of each agent's permissions, never the list
- Explainable 7-signal risk engine with non-tunable hard rules and escalation floors
- Hash-chained audit log with signed checkpoints that catch even an operator rewrite
- Defences against disguised prompt injection: zero-width characters, look-alike letters, full-width letters, number-for-letter spelling, spaced-out letters, base64 and URL encoding
- Admin-token-protected enrolment; per-client rate limits shared across server instances
- MCP proxy that guards any real MCP server
- Operator console: live traffic, agents, attack range (9 scenarios), audit, risk tuning with preview, glossary
- Live threat intelligence on agent IP addresses: GreyNoise, Shodan InternetDB, AbuseIPDB, AlienVault OTX

**How it addresses the problem**
- Impersonation and replay are blocked by the per-call, single-use proof.
- Privilege abuse is blocked by the capability proof.
- Subtle misuse (floods, first contact with an unknown host, injected instructions, leaked secrets) is held for review.
- After-the-fact cover-ups are detectable through the audit chain and checkpoints.

**Expected advantages**
- Stops replay, impersonation and privilege escalation outright.
- Least privilege without revealing an agent's full permissions.
- Every verdict explained in plain words.
- The operator cannot silently rewrite the log.
- Drops in front of existing MCP servers without changing them.

---

## Slide 11 — 5. Approach & Methodology

**Workflow (draw as a flowchart)**
Input → Pre-processing → Processing → Algorithm/Model → Database → Output

| Stage | What happens |
|---|---|
| Input | Sealed agent call plus a single-use challenge (nonce) |
| Pre-processing | Open the encrypted envelope; validate against a strict schema; undo text disguises |
| Processing | Verify the identity proof; spend the nonce once; verify the capability proof; build the request context |
| Algorithm/Model | Score 7 signals; apply weights; apply hard rules and escalation floors |
| Database | Append the audit record (hash chain) and the traffic event to Postgres |
| Output | ALLOW / FLAG / BLOCK with score and reason, sealed back with the next challenge |

**1. Input**
The agent asks for a one-time challenge, signs its call with its secret key against that challenge and the exact request, and seals it to the gateway's public key.

**2. Processing**
- The envelope is decrypted inside the firewall and checked against a strict schema.
- The proof, the single-use nonce and the capability proof are verified.
- Text arguments are normalised: Unicode NFKC folding, invisible characters removed, look-alike letters mapped, base64 and URL encoding decoded.

**3. Algorithms / methods**
- Schnorr proof verification (Fiat–Shamir, over Ed25519)
- Merkle inclusion-proof verification
- Weighted sum of 7 signals: identity 0.30, context 0.25, behaviour 0.15, payload 0.15, threat intel 0.12, rate 0.10, reputation 0.05
- Flag at score ≥ 45; block at ≥ 70
- Hard rules always block: unknown agent, revoked key, unproven identity, replayed challenge, unproven capability, capability escalation
- Escalation floors always flag: payload ≥ 0.75, rate ≥ 0.75, behaviour ≥ 0.6

**4. Output**
A verdict, a 0–100 score and a plain-language reason, sealed back to the agent along with its next challenge. An audit record is appended to the chain.

**5. Evaluation**
- 224 automated tests
- 30 security invariants
- 9 attack scenarios
- 10 disguised-injection cases plus 9 ordinary texts
- A 9-step end-to-end smoke test
- Latency measurements
- Live checks on the deployed system

**Development process (second flowchart)**
Requirement Analysis → Design → Development → Testing → Evaluation

---

## Slide 12 — 6. System Architecture (diagram content)

- **User / Operator:** uses a web browser.
- **AI Agent:** uses the agent SDK to sign and seal its calls.
- **MCP Client:** any agent framework that speaks MCP.
- **Frontend / UI:** Next.js + React console with 7 pages: Overview, Console, Agents, Attack range, Audit, Tuning, Glossary.
- **Backend / APIs:** 15 REST API routes. Every route runs the same guard chain: origin check → rate limit → admin token where required → schema validation.
- **Application logic** (`src/lib/atf`):
  - Identity: Schnorr proofs, nonces, agent registry
  - Crypto: sealed envelopes and sealed fields
  - Capabilities: Merkle proofs
  - Risk engine: 7 signals plus policy
  - Audit: hash chain plus signed checkpoints
  - Threat intel: cached lookups
  - MCP proxy
- **Database:** Neon Postgres, with tables for agents, nonces, events, audit and rate windows.
- **APIs / services:** agent enrolment, challenge, gateway intercept, gateway public key, audit, audit verify, audit checkpoint, traffic, config, config preview, simulate, sealed-field demo, threat intel lookup, health.
- **External components:**
  - Threat intel: GreyNoise, Shodan InternetDB, AbuseIPDB, AlienVault OTX
  - The protected upstream tools (MCP server or API)
  - Vercel serverless hosting
- **Key property:** every path into the application logic passes the same decision function, and a call reaches a protected tool only after an ALLOW.

---

## Slides 13–15 — 7. Demonstration of Modules (show the actual working system)

Screenshots of the live production site are in `submission/screens/`. Run it live at https://agentwall-pbl.vercel.app.

1. **Overview** (`01-overview.jpg`): live interception panel, here a replayed proof blocked.
2. **Attack range** (`03-attack-range.jpg`): capability escalation blocked by a hard rule (a calendar agent tried to charge a card).
3. **Console** (`02-console.jpg`): every call with its verdict, score and reason, plus a risk-over-time chart.
4. **Audit** (`04-audit.jpg`): a forged record detected at the exact record; a saved fingerprint that "Still matches".
5. **Agents** (`05-agents.jpg`): trust scores, a revoked key, and the capabilities each agent has proved in calls.
6. **Tuning** (`06-tuning.jpg`): preview a weight or threshold change; at the defaults, 0 verdicts change.

**Live demo script (about 3 minutes)**
1. On Overview, point at the live panel.
2. On Attack range, run three scenarios:
   - *A legitimate call* → Allowed
   - *Replayed proof* → Blocked
   - *Capability escalation* → Blocked
3. On Audit, click "Try to forge a record" to show the break detected, then click "Save fingerprint".
4. On Tuning, move a slider and show the preview change.

---

## Slide 16 — 8. Results: attack scenarios (test cases and sample predictions)

| Scenario | Attack attempted | Verdict | Score | Stopped by |
|---|---|---|---|---|
| A legitimate call | None (normal work) | ALLOW | 3.2 | — |
| Agent nobody enrolled | Invented identity charges a card | BLOCK | 47.0 | unknown-agent |
| Replayed proof | Captured proof submitted again | BLOCK | 4.8 | replayed-challenge |
| Capability escalation | Calendar agent calls payments | BLOCK | 35.9 | capability-escalation |
| Revoked key still in use | Leaked key keeps calling | BLOCK | 36.3 | revoked-key |
| Rate flood | 41 calls in 10 seconds | FLAG | 11.7 | rate escalation |
| Behaviour that does not fit | Full export to a never-seen host | FLAG | 13.6 | behaviour escalation |
| Prompt injection | Hidden instructions in arguments | FLAG | 16.9 | payload escalation |
| Secrets in a payload | API key riding out in a call | FLAG | 25.5 | payload escalation |

Key callouts:
- **8 / 8** hostile scenarios stopped (4 BLOCK, 4 FLAG).
- **1 / 1** legitimate call allowed.
- **72 / 72** routine seeded calls allowed, so no false alarms.
- A low score can still block: hard rules do not depend on the score.

---

## Slide 17 — 8. Results: graphs (detection and response time)

**Graph 1 — disguised prompt injections caught (out of 10)**
- Before hardening: **1**
- After hardening: **10**
- Disguises covered: zero-width characters, Cyrillic look-alike, full-width letters, number-for-letter spelling, spaced-out letters, punctuation between words, base64, URL encoding, paraphrase.
- Ordinary texts flagged: **0 of 9**.

**Graph 2 — response time (ms)**

| Measurement | Median (p50) | 95th percentile (p95) | Mean | Samples |
|---|---|---|---|---|
| Engine decision (in-process) | 1.77 | 2.04 | 1.83 | n = 500 |
| Full sealed call over HTTP, 2 round trips | 14.34 | 36.44 | 15.34 | n = 20 |
| Full sealed call over HTTP, 1 round trip (challenge returned with verdict) | 11.88 | 15.19 | 12.09 | n = 20 |

HTTP figures were measured against the production build on localhost. Returning the next challenge with each verdict cut the mean latency by about 21%.

---

## Slide 18 — 8. Results: accuracy, precision/recall, testing and system performance

**Headline numbers**
- **224** automated tests passing
- **30** security invariants verified
- **0** known vulnerabilities (`npm audit`)
- **< 2 ms** median decision time

**Precision / recall**

| Evaluation set | TP | FP | FN | TN | Precision | Recall |
|---|---|---|---|---|---|---|
| Attack scenarios (9) | 8 | 0 | 0 | 1 | 1.00 | 1.00 |
| Injection detector (10 attacks + 9 ordinary texts) | 10 | 0 | 0 | 9 | 1.00 | 1.00 |
| Routine seeded traffic (72 calls) | — | 0 | — | 72 | — | — |

These are small, hand-built evaluation sets. A score of 1.00 means no errors on them, not a guarantee against all attacks.

**Live deployment check (agentwall-pbl.vercel.app)**
- All 7 pages return HTTP 200.
- Audit chain is valid across 400+ records in Postgres.
- Enrolment without the admin token is refused (401).
- Rate flood is flagged.
- A fresh checkpoint is consistent with the log.

**End-to-end smoke test:** 9 of 9 checks pass, run against the local production build.

---

## Slide 19 — 9. Conclusion

**Format paragraph**
"The proposed system addresses AI agents that are compromised yet still hold valid credentials. The core implementation has been completed and deployed, including the decision engine, cryptographic identity and capability proofs, the 7-signal risk engine, the hash-chained audit log with signed checkpoints, the operator console and the MCP proxy. Preliminary results indicate that all 8 attack scenarios are stopped, 10 of 10 disguised prompt injections are caught, and routine traffic sees no false alarms, at under 2 ms per decision. The remaining work includes pilot trials with real agent frameworks, load testing, integration and final evaluation."

The template's example says "Approximately 50%". Use your guide's expected figure. The honest status is that the core system is complete and deployed, and only field trials and scale testing remain.

- **Problem addressed:** hijacked agents act through trusted keys, and nothing proves the caller per request or keeps an honest record.
- **Proposed solution:** a zero-trust gateway that proves, authorises and scores every call, then allows, flags or blocks it and logs the decision tamper-evidently.
- **Work completed:**
  - Full decision path
  - 15 API routes
  - 7-page console
  - MCP proxy
  - Postgres storage
  - Live deployment on Vercel
- **Major modules implemented:**
  - Identity
  - Sealed cryptography
  - Merkle capabilities
  - 7-signal risk engine
  - Policy (hard rules and escalation)
  - Audit chain with checkpoints
  - Threat intelligence
  - Admin enrolment
  - Shared rate limiting
  - MCP proxy
- **Preliminary results:** 8 / 8 attacks stopped, 10 / 10 disguised injections caught, 224 tests and 30 invariants passing.
- **Remaining work:**
  - Pilot with real agent frameworks
  - Load testing at scale
  - Automated external anchoring of checkpoints
  - Full Unicode confusables table
  - Optional ML-assisted payload detection

---

## Slides 20–21 — 10. References (IEEE style)

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

The categories the template asks for are all covered:
- Research papers: 1–4, 8–12, 14, 15
- Standards: 5–7, 13, 16–18
- Official documentation: 19–22
- Data sources: 23
- Websites used for technical information: 19–23

The demo agents are synthetic, so there is no training dataset.

---

## Slide 22 — Closing (optional)

- **Thank you: Questions and live demo**
- https://agentwall-pbl.vercel.app
- github.com/krishnashahane/agent-trust-firewall
