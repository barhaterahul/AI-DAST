# AI-DAST-ING — Architecture Diagrams (agent-oriented)

> **Audience:** AI coding agents (and humans) who need a fast, accurate mental
> model of this repo before editing it. Prose details live in
> [`ARCHITECTURE.md`](ARCHITECTURE.md); this file is the *map*. Diagrams are
> Mermaid (renders on GitHub; readable as text). Paths are repo-relative.
> Module path: `github.com/barhaterahul/ai-dast-ing/v4`.

**One-sentence model:** a single Go binary (`cmd/ai-dast-ing`) serves an
embedded React dashboard + REST/WebSocket API (`internal/web`), which launches
per-scan LLM agent loops (`internal/agent`) that call tools
(`internal/tools/*`) against an authorized target, record hypotheses/evidence
in a scan-scoped ledger (`internal/scanctx`), and only report findings that an
independent verifier re-exploits.

---

## 1. System context

```mermaid
flowchart LR
  Op([Operator<br/>browser]) -->|HTTPS/HTTP :9137<br/>session cookie + CSRF| Bin
  CI([CI / backend<br/>automation]) -->|Bearer AIDASTING_API_TOKEN<br/>/api/* + /ws only| Bin
  CLI([Terminal]) -->|flags: --web --setup --start ...| Bin

  subgraph Bin[ai-dast-ing binary]
    direction TB
    UI[Embedded React SPA<br/>internal/web/static ← webui/]
    API[HTTP API + WS hub<br/>internal/web]
    ENG[Agent engine<br/>internal/agent + internal/tools]
    UI --- API --- ENG
  end

  ENG -->|chat + tool calls| LLM[(LLM provider<br/>OpenAI / Anthropic / Gemini /<br/>Ollama / custom base)]
  ENG -->|HTTP, browser, CLI tools<br/>scope-guarded, rate-limited| T[(Authorized target)]
  ENG -->|mint + poll callbacks| OOB[(OOB / interactsh)]
  ENG -->|fetch / refresh JWT| TP[(Operator token API)]
  ENG -.->|optional upstream| PX[(HTTP/SOCKS proxies,<br/>Caido)]
  API -->|severity-gated alerts| N[(Discord / Telegram)]
  Bin <-->|atomic JSON writes| FS[(Data dir<br/>AIDASTING_DATA_DIR)]
  Bin <-->|0600 env file| ENV[(~/.ai-dast-ing.env)]
```

---

## 2. Package layers & dependency direction

Arrows mean "imports / calls". Lower layers never import upper ones.

```mermaid
flowchart TB
  subgraph L0[Runtime]
    MAIN[cmd/ai-dast-ing<br/>main.go · setup.go · exec_*.go]
    TUI[internal/tui<br/>Bubbletea UI]
  end
  subgraph L1[Web platform — internal/web]
    SRV[server.go · handlers_router.go]
    AUTHS[auth_session.go · api_token.go]
    ORCH[orchestrator.go · scan_session.go<br/>queue_state.go · scheduler.go]
    EXPL[exploration_graph/overview/combined.go]
    TOKW[token_providers.go · collection_preview.go<br/>uploads*.go · scan_edit.go]
    PERS[scan_record.go · scan_event_journal.go<br/>retention.go · durability.go]
    WS[ws_hub.go · notify · chat.go · report.go]
  end
  subgraph L2[Agent core — internal/agent]
    LOOP[agent.go Run loop · hooks.go]
    GUARD[agent_guard.go · target_scope.go<br/>tool_scope.go · phase_scope.go]
    PLAN[planner.go · plan_tools.go · surface*.go<br/>recon_*.go · completion.go · convergence_finish.go]
    LEDG[ledger_hooks.go · ledger_tools.go]
    VER[verifier.go · verifier_ledger.go<br/>verify_*.go · oob_verify.go]
    DEEP[authz_matrix.go · probe_*.go<br/>auth_coverage.go · scan_source_*.go]
  end
  subgraph L3[Tools — internal/tools]
    REG[registry.go]
    TSUB[terminal · browser · pageagent · httpclient<br/>python · fileedit · notes · websearch · codesearch<br/>oob · proxy · skills · finish · iolimit]
    AG[agentsgraph — sub-agent graph]
    REP[reporting — report_vulnerability + gates]
  end
  subgraph L4[Domain & infra]
    SCX[scanctx — per-scan state + ledger.json]
    ASF[attacksurface — OpenAPI/HAR/Postman/Bruno/APK]
    HAR[har]
    TPK[tokenprovider — JWT fetch/refresh]
    LLMP[llm · providers · auth — routing, keys, OAuth]
    MTH[methodology — canonical 22 phases]
    SAFE[scopeguard · sandbox · ratelimit · proxy<br/>scanheaders · resources · safe]
    STO[storage — atomic temp+rename]
    PDF[reporting — branded PDF]
    OOBP[oob]
    CFG[config — AIDASTING_* env]
  end

  MAIN --> SRV
  MAIN --> LOOP
  MAIN --> TUI
  SRV --> ORCH --> LOOP
  SRV --> EXPL
  SRV --> TOKW
  ORCH --> PERS
  ORCH --> WS
  LOOP --> REG
  LOOP --> GUARD
  LOOP --> PLAN
  LOOP --> LEDG
  REP -->|verification callback| VER
  REG --> TSUB
  REG --> AG
  REG --> REP
  AG -->|spawns child Agent| LOOP
  LOOP --> LLMP
  LEDG --> SCX
  PLAN --> ASF
  ASF --> HAR
  TOKW --> TPK
  TSUB --> SAFE
  TSUB --> OOBP
  REP --> SCX
  PERS --> STO
  WS --> PDF
  PLAN --> MTH
  L1 --> CFG
  L2 --> CFG
```

---

## 3. Scan lifecycle (request → report)

```mermaid
sequenceDiagram
  autonumber
  participant UI as Dashboard / API client
  participant SRV as web.Server
  participant Q as Admission queue<br/>(queue_state.go, resources)
  participant ORC as Orchestrator<br/>(orchestrator.go)
  participant SES as scanSession<br/>(scan_session.go)
  participant AG as agent.Agent.Run
  participant LLM as LLM
  participant T as Tools → Target
  participant REP as report_vulnerability
  participant V as Verifier agent
  participant DISK as Data dir

  UI->>SRV: POST /api/scan {targets, mode, instruction,<br/>phases, token provider/profiles, context uploads}
  SRV->>Q: admit (AIDASTING_MAX_INSTANCES or RAM headroom)
  Q-->>ORC: slot granted
  ORC->>ORC: mode switch: runSingleTarget / runDASTTarget /<br/>runWildcardTarget (collectSubdomains → per-sub scans) / runMultiScan
  ORC->>SES: executeScanSession (own goroutine + scanctx.ScanContext)
  SES->>AG: NewAgent(...).Run(targets, instruction)
  loop until finish gate passes or budget hit
    AG->>LLM: system prompt (22 phases, scope, plan, ledger) + history
    LLM-->>AG: tool_calls[]
    AG->>AG: guards: scope · phase · passive-recon · rate policy · dedupe
    AG->>T: execute tool (terminal/http/browser/...)
    T-->>AG: result (bounded, archived if large)
    AG-->>SES: Event (tool, thought, phase, finding...)
    SES-->>UI: WS /ws broadcast (live feed)
    SES->>DISK: append events.jsonl
  end
  AG->>REP: report_vulnerability(proof, PoC, CVSS...)
  REP->>REP: gates: method, proof present, FP/claim checks, dedup, CVSS norm
  REP->>V: VerificationRequest (registry-local LLM client)
  V->>T: independently re-exploit
  V-->>REP: verified / exploit-proven / needs-manual-verification
  REP->>DISK: findings → scan.json (atomic)
  SES->>SRV: completion outcome (completion.go: honest status)
  SRV-->>UI: Discord/Telegram notify · PDF via report.go
```

**Scan modes** (`ScanRequest.mode`): `single` (one host, full testing) ·
`dast` (deep crawl → param mining → vuln tests) · `wildcard` (subdomain
enumeration → one sub-scan per subdomain) · multi-target lists go through
`runMultiScan` and the persisted queue (resumable).

---

## 4. Inside one agent loop (`internal/agent/agent.go: Run`)

```mermaid
flowchart TD
  S([Run targets, instruction]) --> PREP[prepareScanEnvironment<br/>auth headers · token roles · context surface seed]
  PREP --> PROMPT[agent_prompt.go<br/>system prompt: methodology + scope + guidance]
  PROMPT --> CALL[LLM chat w/ native tool defs<br/>buildNativeToolDefinitions]
  CALL --> PARSE{tool calls?}
  PARSE -- none --> NUDGE[protocol nudge / unknown-tool recovery] --> CALL
  PARSE -- yes --> DEDUP[dedupeBatchCalls]
  DEDUP --> GUARDS{agent_guard.go<br/>in scope? phase allowed?<br/>rate policy ok?}
  GUARDS -- blocked --> FB[structured rejection → history] --> CALL
  GUARDS -- ok --> EXEC[executeToolAsync<br/>hard timeout per tool · watchdog]
  EXEC --> HOOKS[hooks.go: loop/stuck detection<br/>ledger seeding · surface observe · recon coverage]
  HOOKS --> MSG[agent_messages.go<br/>format result · prune/compact history]
  MSG --> BUD{overBudget?<br/>iterations · duration · tokens ·<br/>tool calls · non-progress}
  BUD -- yes --> END
  BUD -- no --> FIN{finish called?}
  FIN -- no --> CALL
  FIN -- yes --> GATE{finish gates<br/>children collected? proven hyp w/o finding?<br/>plan tasks settled? convergence?}
  GATE -- reject bounded --> CALL
  GATE -- pass / ceiling --> END([completion.go outcome<br/>+ emit finished event])
```

### Multi-agent delegation (`internal/tools/agentsgraph`)

```mermaid
flowchart LR
  C[Coordinator agent<br/>does recon] -->|recon complete →<br/>maybeAutoDelegate| G{{agentsgraph.Graph<br/>one per root scan:<br/>semaphore · cancel ctx ·<br/>shared budget ledger · checkpoint}}
  G -->|spawn_agent| A1[Specialist: authz /<br/>business logic]
  G -->|spawn_agent| A2[Specialist: injection /<br/>server-side]
  G -->|spawn_agent| A3[Specialist: client /<br/>source / API]
  A1 & A2 & A3 <-->|record_hypothesis · add_hypothesis_evidence ·<br/>update_hypothesis · read_ledger · claim_next_hypothesis| L[(Shared ledger<br/>scanctx → ledger.json)]
  C <--> L
  A1 & A2 & A3 -->|results| G -->|check_agent / wait_agent| C
```

Hypothesis lifecycle in the ledger:

```mermaid
stateDiagram-v2
  [*] --> queued: hookLedgerSeed / record_hypothesis
  queued --> testing: claimed by specialist
  testing --> proven: evidence + linked finding
  testing --> rejected
  testing --> blocked
  testing --> exhausted
  proven --> [*]
  rejected --> [*]
  blocked --> queued: precondition met
  exhausted --> [*]
```

---

## 5. Tool surface (what the LLM can call)

Registered in `internal/tools/registry.go` (+ agent-local tools in `internal/agent`).

| Group | Tool names | Implementation |
|---|---|---|
| Execution | `terminal_execute`, `python_action`, `read_tool_output` | `tools/terminal`, `tools/python`, `agent/tool_archive_tool.go` |
| HTTP | `http_request`, `send_request`, `list_requests` | `tools/httpclient`, `tools/proxy` (Caido) |
| Browser | `browser_action` (incl. `verify_xss`), `page_agent`, `discover_client_routes` | `tools/browser` (headless + ext bridge `localhost:38401/ext`), `tools/pageagent` |
| Recon/intel | `web_search`, `cve_search`, `exploit_search`, `code_search`, `scan_source_routes`, `scan_source_sinks` | `tools/websearch`, `tools/codesearch`, `agent/scan_source_*.go` |
| Planning | `build_plan`, `update_plan`, `ingest_har` | `agent/plan_tools.go`, `agent/har_ingest.go` |
| Ledger | `record_hypothesis`, `add_hypothesis_evidence`, `update_hypothesis`, `read_ledger`, `claim_next_hypothesis`, `record_attempt` | `agent/ledger_tools.go` |
| Deep tests | `authz_matrix`, `probe_hypothesis`, `probe_body_contract` | `agent/authz_matrix.go`, `agent/probe_*.go` |
| Verifiers | `verify_sqli`, `verify_ssti`, `verify_xxe`, `verify_csrf`, `verify_path_traversal`, `verify_authbypass`, `verify_timing`, `verify_oob`, `submit_verdict` | `agent/verify_*.go`, `agent/verifier.go` |
| OOB | `oob_callback` | `tools/oob` → `internal/oob` |
| Multi-agent | `spawn_agent`, `create_agent`, `check_agent`, `wait_agent` | `tools/agentsgraph` |
| Memory/files | `add_note`, `read_notes`, `str_replace_editor`, `list_files`, `search_files` | `tools/notes`, `tools/fileedit` (sandboxed by `internal/sandbox`) |
| Knowledge | `list_skills`, `read_skill`, `search_skills` | `tools/skills` (embedded corpus) |
| Output | `report_vulnerability`, `finish` | `tools/reporting`, `tools/finish` |

---

## 6. Context ingestion & authenticated scanning

```mermaid
flowchart LR
  U1[Upload: OpenAPI / Swagger] --> UP
  U2[Upload: HAR] --> UP
  U3[Upload: Postman collection<br/>+ environment] --> UP
  U4[Upload: Bruno dir / zip] --> UP
  U5[Upload: APK / XAPK] --> UP
  UP[POST /api/upload-context<br/>→ dataDir/context/&lt;id&gt;] --> RES[POST /api/collection/resolve<br/>collection_preview.go<br/>env + var overrides + excluded reqs<br/>→ selection.json]
  RES --> ASF[attacksurface.LoadFromPath<br/>normalized endpoints · params · bodies · auth]
  ASF --> SEED[agent/surface_seed.go<br/>typed surface store → planner tasks]

  TPUI[Settings → Token providers<br/>/api/token-providers] --> TPS[(token_providers.json 0600)]
  TPS --> MGR[tokenprovider.Manager<br/>role A = every request<br/>role B = IDOR/BOLA comparison]
  MGR -->|fresh auth header,<br/>refresh before JWT exp| HTTPL[HTTP layer + authz_matrix]
  MGR -->|status| TS[GET /api/token-status/&lt;scan&gt;]
```

---

## 7. Exploration (read-only analytics over finished scans)

```mermaid
flowchart LR
  REC[(scan.json + events.jsonl<br/>+ ledger.json)] --> EG["exploration_graph.go<br/>GET /api/scans/&lt;id&gt;/graph?scope=findings or all"]
  EG --> CHAIN[target → agent lane → tool call → endpoint →<br/>parameter → attempt hypothesis → evidence → finding → tech]
  REC --> OV[exploration_overview.go<br/>GET /api/exploration/overview<br/>grouped by normalized target]
  EG --> CB["exploration_combined.go<br/>GET /api/exploration/combined?scans=a,b<br/>side-by-side lanes g0, g1, ..."]
  CHAIN & OV & CB --> FE[webui pages/exploration.tsx<br/>components/exploration-graph · exploration-overview]
```

---

## 8. Persistence layout (data dir)

```mermaid
flowchart TB
  D[(AIDASTING_DATA_DIR)] --> SD["&lt;target&gt;/&lt;YYYY-MM-DD&gt;/&lt;target&gt;_&lt;slug&gt;/<br/>(orchestrator.go: makeScanDir)"]
  SD --> F1[scan.json — record: meta, findings, status<br/>atomic via internal/storage; immutable once finished]
  SD --> F2[events.jsonl — append-only event journal<br/>partial last line = interrupted append]
  SD --> F3[ledger.json — hypotheses + evidence]
  SD --> F4[notes.json · coverage.json · execution.json<br/>agent graph checkpoint → resume]
  D --> G1[queue_state.json — pending / paused scans]
  D --> G2[token_providers.json · llm_keys.json — secrets, 0600]
  D --> G3[context/&lt;id&gt;/ — uploads + selection.json]
  D --> G4[deleted_findings.json — tombstones]
```

Global-file locations are resolved in `internal/web/data_dirs.go`; verify there before hard-coding paths.

---

## 9. Frontend (`webui/` → embedded at build)

```mermaid
flowchart LR
  subgraph webui/src
    R[router.tsx] --> P[pages/: overview · scans · scan-detail · live ·<br/>new-scan · findings · exploration · schedules ·<br/>token-providers · reports · integrations · settings · login]
    P --> Q[api/queries.ts · api/client.ts<br/>TanStack-style queries → /api/*]
    P --> WSS[store/ws.ts → /ws live events]
    P --> AU[store/auth.ts]
  end
  Q & WSS --> SRV[internal/web]
  B[make build: vite build → internal/web/static<br/>//go:embed static/*] --> SRV
```

`webui/src/methodology-phases.json` is generated from `internal/methodology`:
`go run ./tools/gen-webui-phases > webui/src/methodology-phases.json` — edit the Go source, then regenerate.

---

## 10. Safety boundaries (do not weaken when editing)

```mermaid
flowchart LR
  TC[Tool call] --> SG[scopeguard + agent_guard<br/>host/URL in authorized scope?<br/>local/listener hosts blocked]
  SG --> PG[phase_scope<br/>phase allowed by operator?]
  PG --> RP[agent_ratepolicy + internal/ratelimit<br/>per-domain token bucket]
  RP --> SB[internal/sandbox<br/>filesystem Path_Policy for file tools]
  SB --> IO[iolimit · per-tool hard timeouts · safe.Recover]
  IO --> RED[redactSecrets on emitted events<br/>secrets never returned by API: *_configured booleans]
  RED --> OK([execute])
```

---

## Where to change X (agent quick index)

| Task | Start here |
|---|---|
| Add an API route | `internal/web/handlers_router.go` + handler file in `internal/web/` |
| Add/modify an agent tool | subpackage in `internal/tools/*` → register in `internal/tools/registry.go`; agent-local tools in `internal/agent/*_tools.go` |
| Change the system prompt / methodology text | `internal/agent/agent_prompt.go`, `internal/methodology/` |
| Change finish / completion rules | `internal/agent/completion.go`, `convergence_finish.go`, finish gates in `agent.go` |
| New vuln verifier | `internal/agent/verify_<class>.go` (+ `vuln_classes.go`) |
| Finding gates / verification tags | `internal/tools/reporting/` |
| New context import format | `internal/attacksurface/` (see `postman.go`, `bruno.go`, `collection.go`) |
| Token auth behavior | `internal/tokenprovider/`, `internal/web/token_providers.go` |
| Scan orchestration / modes / resume | `internal/web/orchestrator.go`, `scan_session.go`, `queue_state.go` |
| Persistence format | `internal/web/scan_record.go`, `scan_event_journal.go`, `internal/storage/` |
| LLM providers / routing | `internal/llm/`, `internal/providers/`, `internal/auth/` |
| Config / env vars | `internal/config/` (all `AIDASTING_*`) |
| Dashboard UI | `webui/src/pages/*`, `webui/src/components/*` |

**Build/test:** `make build` (webui + Go binary → `build/ai-dast-ing`), `go test ./...`,
lint via `.golangci.yml`. Use only against targets you are authorized to test.
