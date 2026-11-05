# Forge: execution guide for an agent with a small context window

Status: implementation instructions only. Written 2026-11-03. None of the tasks below is marked implemented by this document.

**Updated workspace decision:** There is one shared workspace and one list of users and profiles. Treat references in older cards to environment selection, environment memberships or environment-isolated profiles as superseded. Keep full/readonly roles, per-user NetBox keys, and actor-scoped NetBox evidence. Existing internal scope IDs are compatibility metadata, not user-facing environments.

This guide breaks the [architecture](architecture.md), [profile editor design](profile-design.md) and [implementation roadmap](implementation-plan.md) into bounded tasks. Those documents explain the design; this one explains what to implement next and how to check it. Current user instructions take precedence. If the documents conflict, record the precise conflict and resolve it before the dependent change; continue unrelated tasks.

## How to execute this guide

Work on **one task card at a time**. Several consecutive cards may fit in one session, but finish and record one before starting another. Do not attempt an entire milestone in one edit. A task that still exceeds the available context should be split into suffixes, such as `T071a`, `T071b`, with the original completion gate preserved. Do not remove requirements to make a card fit.

At the beginning of a session:

1. Read this introduction and `docs/implementation-status.md` if it exists.
2. Inspect the actual working tree and applicable repository instructions. Do not assume an earlier agent completed what it merely described.
3. Find the first unfinished task whose dependencies are satisfied. The numbered order is the default; explicit prerequisites permit unrelated work around external blockers.
4. Read only that card, the referenced design sections, relevant source files and existing tests. Use targeted searches rather than repeatedly loading every document.
5. Write down the intended observable result, files likely to change and the check that will prove it. Implement the smallest complete slice.
6. Run the relevant checks. Review the diff for unintended behavior, secret exposure and scope expansion. Update the ledger with real results.
7. Continue the next ready task when practical. If ending the session, leave a specific next-task ID and any unfinished changes. Do not ask for permission between routine local implementation tasks.

The task cards' paths are proposed workspace-relative locations, not existing files. Keep equivalent established paths once implementation exists. Dependency IDs are minimum prerequisites, not a request to duplicate their work. Add migrations and API contracts alongside the feature that owns them; do not create every future table or empty package in advance.

### Non-negotiable requirements to keep in short-term context

- Backend: Go. Frontend: Svelte 5 + TypeScript + Mineral at `/Users/danil/Development/mineral`. Workspace: `/Users/danil/Develpoment/forge`.
- Profiles use forms, tables and visual previews. Never substitute a YAML/JSON/Kubernetes manifest editor. YAML is allowed for the requested allocation-file import.
- Separate NetBox declarations, desired profiles and observed hardware. Audit never silently repairs infrastructure.
- Each actor uses their own NetBox key. Cache authorization and credential generation matter. Full/readonly must be enforced by the backend.
- Static BMC passwords and optional prefix + last BMC IPv4 octet + optional suffix are required. Serial transforms use declared NetBox data before login. No credential guessing.
- BIOS baselines are captured from reference hosts, published immutably and matched by compatible vendor/model/firmware/registry variants. Pending values are not active compliance.
- A checkbox-approved plan binds exact actions, inputs and identity. Stale inputs require a new plan. Uncertain remote effects are reconciled before replay.
- SQLite and one executor first. PostgreSQL is a later real implementation, not just a connection-string option.
- Ubuntu/Rocky install through customized ISO and Redfish virtual media first. QCOW2 needs a deploy environment; no automatic PXE fallback.
- New cable records do not prove physical cabling. Unsupported capabilities and missing evidence must remain visible.

### Ledger format

Create `docs/implementation-status.md` in T001. Use this format; replace example values with actual state:

```text
Current milestone: A
Next task: T002
Build/tool versions: <verified values>

Task | Status | Evidence | Remaining / next
T001 | done | paths and toolchain inspected; decisions recorded | T002
T002 | in_progress | package compiles; lifecycle check pending | run check

Current contracts: <links to API/types and material decisions>
Files with unfinished changes: <paths and purpose>
External blockers: <exact missing version/image/lab target, dependent IDs>
Last checks: <command, result, environment; not merely "tested">
Qualification: <simulated / VM-tested / physical model+firmware tested>
```

Statuses: `todo`, `in_progress`, `done`, `blocked_external`. A blocked task is not done. “Implementation complete; hardware test missing” must retain the missing qualification gate. Keep a short completed-task table and move lengthy logs into linked artifacts; do not copy the entire chat into the ledger.

### Check commands and completion evidence

T002/T003 establish these commands; they do not exist yet:

- `make test-go`: Go tests; use targeted package tests during a card.
- `make check-web`: TypeScript/Svelte checks.
- `make test-web`: meaningful UI/component tests.
- `make build`: frontend followed by embedded backend build.
- `make test-integration`: local fixture/database integration tests, no production targets.
- `make test-vm`: explicitly configured Linux VM installer tests added later.

Do not fabricate successful output. Distinguish not-run from failed. Run a milestone's combined checks once after its cards pass; repeat only for new changes or unresolved failures. For simple styling, a browser/manual check can be more useful than a test that only repeats class names. Core identity, authorization, state transitions, disk targeting and retry logic require behavioral tests.

### Shared fixture story

Use small deterministic fixtures throughout: `host1` and `host2` selected, `host3` unselected; two environment scopes; user A/full with wider NetBox access and user B/readonly with narrower access. Give host1 BMC IPv4 `10.20.30.47`. Add two physical uplinks, two stable boot disk identities, two leaf switches/fabrics, one good BIOS reference and one incompatible model. All serials, passwords and endpoints are fake.

Allocation fixture: `ctl_ips` and `tun_ips`, with entries for all three hosts. Only selected hosts generate intent. Include variants for a wrong serial, missing interfaces/IPs, wrong VRF, port collision, 429, lost POST response and active/pending BIOS mismatch. Keep scenario variations isolated so a failure explains one behavior.

### Milestone map

| Milestone | Cards | Demonstrable result |
|---|---|---|
| A | T001–T010 | Running Mineral app, SQLite, named users, roles and secrets |
| B | T011–T016 | Durable jobs and recoverable event UI |
| C | T017–T024 | Per-user NetBox inventory with rate control |
| D | T025–T032 | Published form-based profiles and BMC credential recipes |
| E | T033–T040 | Cached hardware inspection and reference-host BIOS compliance |
| F | T041–T049 | Network/allocation/hardware audit and findings UI |
| G | T050–T056 | Reviewed, approved and verified NetBox repairs |
| H | T057–T062 | Cabling workflow and XLSX; first substantial release |
| I | T063–T090 | Artifact/build/deploy flow; real Ubuntu/Rocky qualification |
| J | T091–T100 | FreeIPA, PostgreSQL, backup/recovery and operational release |
| Extensions | E001–E008 | Explicitly qualified additional capabilities |

## A. Application foundation

Read architecture sections 1–4, 12–14 and profile design section 1 as needed.

### T001 — Record the starting state

**Needs:** none. **Work area:** `docs/implementation-status.md`, `docs/compatibility.md`.

1. Inspect repository files and instructions; record any existing code and working changes.
2. Inspect installed Go/Node/package-manager versions and Mineral's package/exports. Record actual versions without installing arbitrary upgrades.
3. Create the ledger and a compatibility matrix with unknown NetBox version, exact Gigabyte/Lenovo/Yadro models/firmware and Ubuntu/Rocky releases.

**Check:** paths are correct, no unknown compatibility is marked supported, and the ledger points to T002. Do not contact live infrastructure or initialize unrelated services.

### T002 — Start a minimal Go HTTP service

**Needs:** T001. **Work area:** `go.mod`, `cmd/forge`, `internal/httpapi`, build scripts.

1. Select the module path from available repository context; if no remote exists, use a documented temporary local module name.
2. Add configuration parsing, HTTP server startup, `/healthz`, structured logging and graceful shutdown.
3. Add an API error shape containing code, message and correlation ID; keep stack traces out of client responses. Establish Go test/build targets.

**Check:** health returns the expected response, invalid required configuration fails clearly, shutdown exits cleanly, and Go tests/build pass. No fake inventory endpoint yet.

### T003 — Render Mineral in Svelte

**Needs:** T001. **Work area:** `web/`, frontend package lock and build scripts.

1. Create Svelte 5 + TypeScript + Vite with a single application shell.
2. Install/use the actual Mineral package and styles/fonts. Render a Panel, Button, Field and Input; initialize browser-only themes correctly.
3. Add frontend check/test/build scripts. Document a reproducible pinned package source/archive for CI instead of depending solely on the absolute local path.

**Check:** the page renders with real Mineral styling, keyboard labels work, frontend checks/build pass. Do not copy or redesign Mineral.

### T004 — Serve frontend and API together

**Needs:** T002, T003. **Work area:** frontend embedding/static handler, API client wrapper, application navigation.

1. Embed built SPA assets through an appropriate Go package; order the build so embed inputs exist.
2. Add SPA navigation fallback while keeping `/api/*` missing routes as API errors.
3. Add a typed API wrapper and initial OpenAPI contract. Display backend connectivity/error state in the UI.

**Check:** one built binary serves assets and health/API; refreshing a frontend route works; a nonexistent API route does not return HTML.

### T005 — Open and migrate SQLite

**Needs:** T002. **Work area:** `internal/store`, `internal/store/sqlite`, migrations/config.

1. Add a repository/transaction boundary and migration runner; choose and pin a SQLite driver.
2. Configure foreign keys on connections, local-disk WAL, busy timeout and bounded write connections. Introduce UUID/time/row-revision conventions.
3. Add a disposable database test helper. Keep network calls outside transaction callbacks.

**Check:** empty database migration and reopen succeed, FK violations fail, migration rerun is safe, and bounded concurrent read/write behavior is tested.

### T006 — Persist users and environment membership

**Needs:** T005. **Work area:** `internal/auth`, user/environment tables and repositories.

1. Implement users with exactly `full`/`readonly`, disabled state and stable IDs.
2. Implement environments and memberships, with an authorization service accepting actor, action and environment/object scope.
3. Define an authentication-provider interface suitable for local tokens now and FreeIPA later.

**Check:** role/action and environment-scope table tests cover allow/deny and disabled users. Do not add a hidden superuser product role.

### T007 — Implement first-run bootstrap and login tokens

**Needs:** T006. **Work area:** bootstrap/auth services, token/session repositories and API.

1. Use `FORGE_BOOTSTRAP_TOKEN` to create the first named full user in a transaction; disable first-run setup afterwards.
2. Issue high-entropy named-user tokens, show them only once and store hashes. Add full-user management of named full/readonly users.
3. Add rate-limited authentication and revocation. Do not use one shared bootstrap identity for normal multiuser activity.

**Check:** concurrent bootstrap creates one initial setup; invalid/revoked tokens fail; cleartext issued tokens are absent from stored rows and logs.

### T008 — Add browser sessions and authorization middleware

**Needs:** T007, T004. **Work area:** auth HTTP middleware, login screen, navigation.

1. Exchange login credentials for secure HttpOnly/SameSite session cookies; configure production HTTPS and an explicit local development mode.
2. Add CSRF protection, expiry/logout and backend role/environment enforcement.
3. Implement login/logout/current-user UI; hide unavailable operations while keeping backend checks authoritative.

**Check:** missing/expired session, CSRF violation, readonly mutation and disabled user are rejected by direct API requests. Login/logout works through the browser.

### T009 — Store encrypted secrets

**Needs:** T006. **Work area:** secret resolver/storage and environment secret controls.

1. Use standard authenticated encryption with a stable configured key, random nonce, key ID and owner/environment binding. Keep the encryption key separate from the bootstrap token.
2. Expose create/replace/reference metadata; do not return recoverable secret values on read routes.
3. Add central sanitization for credentials, Authorization headers, grant URLs and known secret-bearing fields.

**Check:** decrypt works after restart with the correct key, wrong-key/tampered ciphertext fails, access scopes hold and errors/logs exclude test secrets. Do not invent custom cryptography.

### T010 — Add a deterministic local simulation mode

**Needs:** T004, T008, T009. **Work area:** local simulator configuration, fixture loading, developer instructions.

1. Create explicitly fake local scenarios using the shared fixture story; isolate their DB/artifacts from production configuration.
2. Show “Simulation” in the UI; do not silently enable fixtures when a real adapter fails.
3. Document start/login/reset commands and run the A milestone smoke check.

**Check:** a clean developer setup opens the Mineral app with named roles, and leaving simulation mode cannot accidentally retain fake provider credentials/endpoints. Mark A complete only with these checks recorded.

## B. Durable jobs

Read architecture sections 11, 12 and API/SSE behavior in section 14.

### T011 — Persist jobs, steps and events

**Needs:** T005, T006. **Work area:** `internal/jobs`, jobs/steps/events migrations.

1. Define explicit job/step statuses, actor/credential references, input hash, attempt count, next eligible time and deadline.
2. Persist ordered events with monotonic IDs; insert job and its initial event transactionally.
3. Add an injected clock and deterministic identifiers for tests. Job payloads contain secret handles, never decrypted secrets.

**Check:** state transition rules reject illegal transitions, events preserve order, and a persisted job survives reopening the DB.

### T012 — Claim jobs and lease resources

**Needs:** T011. **Work area:** scheduler/repositories and single-executor host lock.

1. Claim eligible jobs atomically in a short transaction with worker/lease/fencing-generation fields.
2. Enforce one active SQLite executor process; add bounded worker concurrency and unique resource leases.
3. Release DB transactions before invoking work. Heartbeat/renew active claims and use an injectable clock for expiry.

**Check:** two simulated claimers do not receive the same active job/resource; a second executor is rejected; expired leases are visible but do not automatically authorize remote-effect replay.

### T013 — Add scheduled retries, deadlines and cancellation intent

**Needs:** T012. **Work area:** scheduler and job control API.

1. Represent backoff with `next_attempt_at`; waiting work must not hold a worker or transaction.
2. Classify errors as terminal/retryable/needs-attention and cap attempts/elapsed time.
3. Implement cancellation requested versus completed, with step-specific safe boundaries.

**Check:** fake time advances a retry; deadline expires predictably; cancellation does not mark a still-running remote action rolled back.

### T014 — Recover interrupted external-effect steps

**Needs:** T013. **Work area:** durable step runner and simulated external service.

1. Persist intent before dispatch and result afterward; represent `sent`, `confirmed`, `uncertain` explicitly.
2. Add a reconciliation hook before replaying interrupted steps; remote operation references survive restart.
3. Test a fake external action that succeeds while its response is lost. Park inconclusive reconciliation as `needs_attention`.

**Check:** restart does not blindly dispatch the action twice. Do not introduce real NetBox/BMC mutations in this card.

### T015 — Expose idempotent job creation and SSE

**Needs:** T014, T008. **Work area:** job APIs/OpenAPI and event streaming.

1. Scope request idempotency keys to actor/route/body hash; duplicates return the existing job, differing bodies conflict.
2. Add authorized status/events/cancel routes and SSE replay from the last event ID.
3. Filter event payloads and enforce current authorization when connecting and while streaming.

**Check:** duplicate HTTP submits make one job; reconnect resumes ordered events; revoked/unauthorized users cannot keep reading protected events.

### T016 — Build the job timeline screen

**Needs:** T015. **Work area:** jobs list/detail UI and simulated harmless workflow.

1. Show stages, event times, attempt history, retry time, cancellation intent and actionable failure reasons.
2. Reconnect SSE without duplicating rows; show offline/stale state explicitly.
3. Demonstrate a harmless multistep job across server restart and record B milestone results.

**Check:** UI reflects persisted status after refresh; no fake progress percentages are inferred for unknown-duration remote work.

## C. NetBox inventory

Read architecture sections 3 and 6. Keep all adapter work read-only until milestone G.

### T017 — Manage each user's NetBox credential

**Needs:** T009, T008. **Work area:** NetBox instances/credentials storage, own-credential form/API.

1. Store endpoint, credential owner, encrypted key reference and rotation generation.
2. Permit full/readonly users to manage only their own key; reject duplicate key fingerprints registered to different users.
3. Add explicit test/replace/delete controls and invalidation of dependent cache visibility on rotation/revocation.

**Check:** user B cannot read/use user A's key; the API returns metadata only; rotation changes generation. Do not add a global fallback key.

### T018 — Discover and report API compatibility

**Needs:** T017. **Work area:** `internal/adapters/netbox`, compatibility UI/fixtures.

1. Inspect available version/status/schema metadata through the actor's key; handle unavailable metadata without guessing.
2. Build a compatibility object with known, unknown and unsupported capabilities.
3. Record the versioned fixture basis and show why writes are disabled for unqualified versions.

**Check:** known fixture detection, absent metadata, permission denial and an unknown major version produce distinct honest outcomes.

### T019 — Build bounded read transport and pagination

**Needs:** T018. **Work area:** NetBox HTTP client and fixtures.

1. Add validated endpoints/TLS, timeouts, body-size limits and cancellation; constrain redirects/pagination URLs to the configured trusted service.
2. Follow pagination to completion, translate errors and track snapshot completeness.
3. Keep raw DTOs separate from normalized domain objects; never log auth headers or secret query parameters.

**Check:** multi-page collection, pagination loop/bad next URL, oversize body, cancel and mid-page failure. Incomplete fetch must not imply deletion.

### T020 — Rate-limit and coalesce NetBox reads

**Needs:** T019, T013. **Work area:** host request scheduler and scoped read coalescing.

1. Add shared host token bucket/cooldown, concurrency caps and per-user fairness; start from architecture defaults.
2. Parse seconds/date `Retry-After`; defer job retry without holding a worker. Missing header uses bounded jittered backoff.
3. Coalesce only matching user/credential-generation requests. Limit retry budget; do not generic-retry mutations.

**Check:** two users share host cooldown but never share authenticated results; fake-time tests prove no early retry or busy loop and no starvation.

### T021 — Normalize inventory and freeze selections

**Needs:** T020, T005. **Work area:** inventory domain, server/snapshot/selection tables.

1. Normalize devices and required related interfaces/MACs/IPs/VRFs/prefixes/VLANs/racks/cables in bounded chunks.
2. Key servers by instance/device ID; preserve identity through renames. Store source timestamps/hashes/completeness.
3. Freeze explicit selected IDs separately from the saved filter. Treat confirmed deletion, filtering and permission loss differently.

**Check:** host3 never joins an existing selection merely because a filter changes; rename keeps UUID; failed page/403 does not tombstone a server.

### T022 — Enforce scope on cached and derived inventory

**Needs:** T021, T008. **Work area:** visibility service and inventory APIs.

1. Partition API caches by instance/user/credential generation/request and implement bounded visibility proofs.
2. Gate server/related-object access by both environment and current NetBox visibility; fail closed when sensitive access cannot be established.
3. Expose a reusable authorization method for future findings/jobs/exports and invalidate proof on token changes.

**Check:** B's narrower scope hides A-only servers and related data even if cached globally; guessed server IDs and stale proofs cannot bypass checks.

### T023 — Build inventory filters and details

**Needs:** T022, T004. **Work area:** inventory and server screens.

1. Add paginated server-side filters, explicit selection count and saved filters. Debounce typing and cancel stale UI requests.
2. Show NetBox fields, interface/IP graph, cables and snapshot freshness; distinguish unavailable data from empty data.
3. Offer explicit refresh through durable jobs, subject to role and request budget; no hidden hardware probe on page view.

**Check:** selections remain stable across pages, stale search responses do not overwrite new ones, and readonly users cannot trigger forbidden operations.

### T024 — Qualify the read-only inventory slice

**Needs:** T023, T016. **Work area:** integration scenario, compatibility report and ledger.

1. Run the two-user fixture with pagination, 429 and a revoked key; measure requests to demonstrate bounded related-object fetches.
2. Verify restart preserves selected IDs/snapshots while keeping freshness honest.
3. If a real NetBox endpoint/key is already authorized and available, perform scoped read-only compatibility discovery; otherwise record that qualification as blocked externally.

**Check:** C's fixture slice passes; real version remains unknown until measured. No write-capable test call is allowed as a “permission check.”

## D. Profiles and connection credentials

Read architecture section 5 and profile design sections 1–2, 8.

### T025 — Store profile drafts and published revisions

**Needs:** T005, T008. **Work area:** `internal/profiles`, profile/revision/assignment tables and API.

1. Define typed profile identity/kind and kind-specific payloads, starting with connection profiles. Avoid a universal untyped map for domain validation.
2. Add draft save, server-side validation, publish immutable revision, clone and archive.
3. Hash canonical nonsecret configuration and pin references; protect draft updates with row revision checks.

**Check:** editing a draft cannot change published bytes; concurrent edit conflicts; readonly publish fails; referenced published revisions remain available.

### T026 — Build profile list and form shell

**Needs:** T025, T003. **Work area:** `web` profile routes/shared controls.

1. Show kind/name/revision/draft/match count and create/duplicate/edit/publish/archive actions.
2. Build labelled form sections with linked validation summary and save-versus-publish behavior.
3. Add accessible dialogs, focus handling and unsaved-change handling using Mineral controls.

**Check:** create/save/reopen a connection draft through the UI; readonly view works. There is no profile manifest text editor.

### T027 — Resolve profile applicability

**Needs:** T025, T021. **Work area:** selector types/resolver and applicability controls.

1. Implement typed environment/vendor/model/role/site/rack/tag/custom-field criteria and explicit priority.
2. Resolve explicit server assignment first, otherwise unique highest-priority match; reject ties and missing required references.
3. Pin referenced revisions and typed overrides into a `ResolvedSpec`; expose selected-server impact preview.

**Check:** equal priorities fail, revision changes do not mutate old resolutions, and the UI explains which rule selected a profile.

### T028 — Resolve a canonical BMC target

**Needs:** T027, T022. **Work area:** connection profile endpoint fields and target resolver.

1. Add NetBox custom-field/management-binding/per-server endpoint sources and explicit system selector.
2. Parse/validate IP, port, allowed network and TLS settings. For hostname cases use explicit bound IPv4 or an unambiguous documented policy, with separate TLS name.
3. Return one immutable canonical target containing source fingerprints; reuse this object for transport and password derivation.

**Check:** management IP wins over unrelated primary IP, ambiguity fails, private allowed networks work, and source address changes invalidate a prior resolution.

### T029 — Implement static BMC password mode

**Needs:** T028, T009. **Work area:** credential resolver and connection password controls.

1. Select an existing scoped secret or enter/store a password securely; keep username separate.
2. Resolve credentials only inside the connection operation; keep cleartext out of plans and API DTOs.
3. Add meaningful masked labels and rotation metadata without a stored-secret reveal route.

**Check:** correct environment access, persistence/restart and logs/preview masking; saving a profile never changes the remote password.

### T030 — Implement IPv4-octet password mode

**Needs:** T029. **Work area:** pure derivation function and `CredentialRecipe` form.

1. Add optional prefix secret, BMC last-octet value, decimal padding and optional suffix secret.
2. Extract from the canonical parsed target, derive only in memory, and preview only nonsecret extracted value/recipe.
3. Add validation and source/secret-generation invalidation. Do not try formatting variants after auth failure.

**Check:** fake secrets `P`/`S` yield `P47S`, `47S`, `P47`, `P047S`; `.7`, `.0`, `.255`, invalid/IPv6 input and no prefix/suffix are covered. Real secret output never appears in UI/logs/storage.

### T031 — Add bounded serial-derived segments

**Needs:** T030. **Work area:** typed recipe segment model and advanced form controls.

1. Add declared NetBox serial source, trim/case transforms and explicit substring/from-end controls with documented indexing.
2. Reject too-short/missing serial and invalid transforms; never depend on post-login Redfish data.
3. Keep the simple octet preset primary; advanced editing uses rows/dropdowns, no expression or template interpreter.

**Check:** first-login derivation works from declared data; too-short Unicode/ASCII inputs fail as specified; unsupported operations and recursive references are rejected.

### T032 — Integrate profile preview and publish

**Needs:** T026–T031. **Work area:** connection form, profile impact UI and integration tests.

1. Wire selectors, endpoints, static/derived modes, trust settings and masked preview into one complete form.
2. Publish a profile and assign its pinned revision; editing/rotation shows affected-server impact and stale-resolution state.
3. Keep “Test connection” disabled with a clear reason until T034 supplies the inspector. No fake success response.

**Check:** an operator can author all credential modes without source editing; D milestone form and backend checks pass.

## E. Hardware observations and BIOS baselines

Read architecture sections 7–8, especially BIOS baselines, and profile design section 3.

### T033 — Define inspection contracts and observation storage

**Needs:** T011, T028. **Work area:** `internal/observations`, driver interfaces and observation tables.

1. Define capability states and normalized identity/CPU/RAM/NIC/disk/controller/BIOS domains with explicit units and coverage.
2. Store immutable observations with driver/profile versions, start/end time, source identity, validity and sanitized raw payload.
3. Implement fixture inspector; separate last-known-good observation from latest failed attempt.

**Check:** an unavailable domain is unknown, not an empty successful inventory; a failed refresh preserves the last-good record with a stale indicator.

### T034 — Discover Redfish and test a connection

**Needs:** T033, T032, T020. **Work area:** `internal/adapters/redfish`, connection-test action.

1. Implement bounded authenticated discovery from the service root; follow trusted resource links and require a unique/explicit system selection.
2. Use the resolved target and credentials; keep one operation per BMC and do not guess alternate credentials after denial.
3. Wire the explicit connection-test button to a durable read-only discovery job; report capabilities and identity without changing hardware.

**Check:** nonstandard system paths, multiple systems, TLS failure, auth failure and missing resources are distinct. No hardcoded `/Systems/1`; no media/power/configuration actions during test.

### T035 — Collect and normalize hardware

**Needs:** T034. **Work area:** Redfish resource collectors and hardware normalization.

1. Collect system/chassis serial/UUID/model/firmware, CPU, DIMM, physical NIC, drive, controller and volume resources when exposed.
2. Preserve raw identifiers and normalized units; distinguish BMC/shared NIC, physical port and virtual interfaces.
3. Persist partial failures by domain and source; sanitize payloads before writing them to the DB.

**Check:** missing NIC resource, duplicate serials, unknown capacity and vendor field variations never manufacture a healthy result; normalization fixtures preserve stable identities.

### T036 — Cache inspection jobs and display hardware evidence

**Needs:** T035, T016, T023. **Work area:** observation scheduling, server hardware tab.

1. Coalesce equivalent authorized inspection requests, honor TTL and expose explicit refresh for full users.
2. Show NetBox versus observed identity, hardware components, coverage and age; a serial mismatch is prominent.
3. Add per-host/NIC identity binding suggestions using MAC/PCI/port evidence, with explicit operator resolution for ambiguity.

**Check:** page refresh does not re-probe BMC; failed refresh retains stale evidence; readonly access is scoped; ambiguous port mapping never silently chooses the first NIC.

### T037 — Collect active and pending BIOS data

**Needs:** T035. **Work area:** BIOS/registry collectors, normalized BIOS domain and server BIOS tab.

1. Discover the BIOS resource, attribute registry and settings links from observed resources.
2. Store active values, pending values and registry metadata separately; hash the registry content and retain model/firmware context.
3. Display typed attributes with native keys, descriptions, allowed values/read-only/dependency metadata when available. Sanitize sensitive fields.

**Check:** active mismatch plus pending desired value remains visibly distinct; missing registry/permission/unsupported resource is not a pass; reused registry ID with changed content is detected.

### T038 — Capture a baseline through the UI

**Needs:** T037, T025, T026. **Work area:** BIOS profile types and capture wizard.

1. Add “Create BIOS profile from this host” using an authorized recent observation and explicit reference provenance.
2. Pre-exclude secrets, host identifiers, transient values and device-specific boot paths. Let operators select appropriate attributes and typed expected values.
3. Default applicability narrowly to observed vendor/model/SKU/firmware/registry compatibility; preview and publish an immutable revision.

**Check:** capture performs no BIOS writes, source-host changes do not change published expectations, unknown-sensitive values are excluded, and the operator never edits a manifest.

### T039 — Compare model-compatible BIOS variants

**Needs:** T038, T027. **Work area:** BIOS variant matching and pure comparison service.

1. Allow one named profile to hold separately captured compatible-family variants; reject overlapping matches.
2. Compare typed native active values, explicitly classify no variant/missing evidence, and show desired pending values as pending rather than compliant.
3. Add recapture-to-draft with a diff; widening compatibility requires explicit operator review/evidence.

**Check:** compatible match/mismatch, incompatible model, registry change, missing attribute, overlapping variants and recapture immutability are covered. No cross-vendor string-name equivalence is assumed.

### T040 — Qualify inspection and baseline workflows

**Needs:** T036, T039. **Work area:** end-to-end fixture scenarios and compatibility matrix.

1. Exercise inspect → cache/restart → capture baseline → compare peers → revise draft through UI/API.
2. Add sanitized vendor fixtures when actual read-only evidence is available; isolate generic support from qualified model/firmware facts.
3. Record unavailable hardware evidence and capabilities honestly. Preserve independent work if real vendors are inaccessible.

**Check:** E's functional flow passes against fixtures; each live support claim has model/firmware and observation evidence. BIOS mutation is still unimplemented, not silently enabled.

## F. Network intent and audits

Read architecture sections 5, 8 and profile design sections 3–4, 8.

### T041 — Define the network graph and validate it

**Needs:** T025, T036. **Work area:** network profile domain and pure validator.

1. Model physical bindings, bonds, VLANs and supported bridges as typed nodes/relationships, with separate OS/NetBox names.
2. Validate unique names, acyclic parents/membership, valid bond members, VLAN IDs, MTUs and unsupported nesting.
3. Separate NetBox VRF references from explicit Linux VRF devices/routing tables. Resolve every object reference in an instance/environment scope.

**Check:** cycles, duplicate names, incompatible MTU and accidental Linux-VRF creation from an IPAM VRF fail meaningful tests.

### T042 — Build the network profile editor

**Needs:** T041, T026, T022. **Work area:** network tree/table, object pickers and preview.

1. Add physical/bond/VLAN/bridge controls using Mineral forms and labelled member/parent selectors.
2. Add network rows for prefix, VRF, VLAN, allocation-group name, routes, DNS and primary-IP policy.
3. Show topology plus per-server physical identity bindings and field-level validation. Stable IDs remain behind readable contextual labels.

**Check:** create a two-uplink bond with two VLANs through forms, save/reopen/publish, and display a per-host resolved preview. No drag-only or text-only configuration requirement.

### T043 — Parse allocation maps as bounded data

**Needs:** T021, T041. **Work area:** allocation parser/import storage.

1. Parse YAML map groups safely with document size/depth limits and duplicate-key rejection; never evaluate Ansible/Jinja or expressions.
2. Resolve selected-device host keys via exact names/explicit aliases; reject ambiguous selected aliases and missing required entries.
3. Ignore unselected hosts for intent generation while reporting their count. Persist import hash, parser version and selected binding/mapping metadata.

**Check:** host3 generates no action; malformed YAML fails; unrelated scalar-entry errors do not block valid selected entries; selected wrong types and duplicate keys fail.

### T044 — Resolve addresses and preview allocation bindings

**Needs:** T043, T042, T022. **Work area:** allocation/network resolution and import UI.

1. Map imported groups to network rows with dropdowns and parse selected addresses using `net/netip`.
2. Validate prefix/mask/VRF/interface binding and conflicts, distinguishing the null/global VRF explicitly. Support deliberate IPv6 input contracts without guessing scalar semantics.
3. Show only selected assignments, source group/key and row errors; hide unauthorized competing-object details while still blocking conflicts.

**Check:** same IP in different VRFs versus duplicate in one VRF, wrong prefix, missing interface and incorrect mask have distinct outcomes; extra hosts remain ignored.

### T045 — Build hardware compliance forms and pure rules

**Needs:** T036, T026. **Work area:** hardware profile editor and `internal/compliance` rules.

1. Add typed required-field, serial/model, CPU/RAM/NIC/disk and audit-only RAID expectation controls.
2. Define rule result statuses, severity and install-blocking policy separately; attach source/evidence and expected/actual values.
3. Evaluate solely against resolved profiles and stored snapshots/observations, with no network calls or repair side effects.

**Check:** identity mismatch blocks installation, missing observation is unknown, unexpected interface is a finding without deletion, and insufficient NIC coverage cannot pass completeness.

### T046 — Persist complete audit runs

**Needs:** T045, T039, T044, T011. **Work area:** audit orchestration, finding tables and rule adapters.

1. Freeze profile revisions, selection, NetBox/observation IDs and allocation hashes into audit inputs.
2. Evaluate hardware, BIOS, interface graph, addresses and documented/observed cable rules; store deterministic findings.
3. Keep `error`, `unknown`, `not_applicable` and `fail` distinct. Required BIOS coverage gaps block installation even when no variant applies.

**Check:** identical frozen inputs yield identical findings; running an audit makes zero infrastructure mutation calls; active/pending BIOS expectations retain correct status.

### T047 — Display findings and narrowly scoped waivers

**Needs:** T046, T023. **Work area:** audit list/detail, evidence drawers and waiver controls.

1. Group/filter findings by host/category/status/severity and expose evidence age and expected/actual values.
2. Implement full-user waivers bound to exact finding scope with reason/expiry; changed inputs invalidate them.
3. Prohibit waiving wrong host identity or ambiguous destructive disk selection. Preserve current visibility on findings and exports-to-be.

**Check:** readonly cannot waive, expired/scope-changed waivers do not suppress blockers, and unknown evidence is not styled as a successful pass.

### T048 — Compose onboarding bundles and overrides

**Needs:** T027, T039, T042, T045. **Work area:** bundle editor/resolution preview.

1. Add profile pickers with explicit published revision pins and per-server identity bindings/typed overrides.
2. Show which required pieces are absent and why a selected server is incompatible. Installation/storage references can remain explicitly unconfigured until their feature cards.
3. Generate immutable bundle resolutions for audits; updating a profile does not silently update a pinned bundle.

**Check:** complete audit-only bundle resolves without installation support; a requested install remains blocked until its required profiles exist.

### T049 — Close the audit milestone

**Needs:** T047, T048. **Work area:** scenario tests and ledger.

1. Run selected hosts plus ignored allocation hosts through profile resolution, stored inspection, BIOS comparison and network/hardware audit.
2. Verify zero remote writes and prove wrong serial/VRF/unknown evidence remain actionable blockers.
3. Record F milestone checks and any measured request counts; do not label repair buttons functional until milestone G.

**Check:** the user can perform the complete form → import → audit → findings workflow with stable results after refresh/restart.

## G. Approved NetBox remediation

Read architecture section 8's plan/approval contract and section 11's uncertain-effect recovery.

### T050 — Define typed actions and dependency graphs

**Needs:** T046, T014. **Work area:** `internal/plans`, plan/action/dependency tables.

1. Define allowlisted action types with field-limited before/after, preconditions, capabilities, verification and recovery behavior.
2. Compile repairable findings into a DAG; keep investigation/manual tasks separate. Include actual prerequisite relationships.
3. Compute deterministic plan/input hashes and reject cyclic/unknown dependencies. Do not accept client-provided authoritative diffs.

**Check:** create-interface → bond/VLAN → IP → primary-IP ordering is valid; unexpected objects do not compile into destructive deletion actions.

### T051 — Implement approval selection and review UI

**Needs:** T050, T047. **Work area:** approvals backend and checkbox/diff screen.

1. Select a dependency-closed action subset with visible prerequisite additions/removals.
2. Store actor/time server-side, exact plan revision/digest and selected action IDs; selected changes need a new approval revision.
3. Show field-level before/after and impact summary; keep future destructive hardware/install approvals separate.

**Check:** selecting primary-IP includes prerequisites visibly, deselecting prerequisites blocks/removes dependents, and unrelated cables/install actions stay unselected.

### T052 — Validate plans immediately before execution

**Needs:** T051, T022, T012. **Work area:** plan preflight/executor boundary.

1. Recheck full actor/environment/credential generation and supported NetBox write capabilities.
2. Acquire resource leases in stable order; refresh touched objects and target identity regardless of display-cache TTL.
3. Reject changed inputs/diffs; use conditional updates where verified and expose remaining best-effort limitations on older APIs.

**Check:** role loss, rotated token, changed address/serial, external object edits and stale approved revision prevent dispatch. An approved plan is not a permanent authorization bypass.

### T053 — Apply interface and relationship actions

**Needs:** T052, T019. **Work area:** NetBox write adapter for interfaces/MACs/relations.

1. Implement the tested-version DTO translations for creating missing physical/logical interfaces and approved parent/LAG/MAC changes.
2. Persist intent/results/created IDs, patch only approved fields and verify returned/observed state.
3. Stop dependent actions on failure; allow unrelated approved host branches according to batch policy.

**Check:** lost response and re-run do not create duplicate interfaces when reconciliation proves an existing effect; a field outside the approved diff is unchanged.

### T054 — Apply IP assignment and primary-IP actions

**Needs:** T053. **Work area:** IPAM write adapter and action verifiers.

1. Implement exact-address create/assign/reuse rules with correct VRF, CIDR and destination interface.
2. Refuse silent reassignment from another device or substitution of a “next available” address. Recheck conflicts immediately before writing.
3. Implement primary-IP changes only after verified assignment and preserve created IDs for reconciliation.

**Check:** wrong-VRF/conflicting IP fails; identical address in a different allowed VRF is handled intentionally; double submit does not duplicate approved operations.

### T055 — Reconcile uncertain writes and partial plans

**Needs:** T054, T014. **Work area:** action reconciliation and execution UI.

1. Query known IDs/natural keys after timeout/restart; adopt only uniquely established effects with matching intent.
2. Mark ambiguity `needs_attention`; never generic-retry a POST. Persist which actions succeeded versus blocked/uncertain.
3. Add post-apply re-audit and explicitly safe compensations only; do not claim cross-model NetBox transactions.

**Check:** response lost after success, two possible matching objects, failed dependency, revoked credential mid-plan and conditional update conflict produce recoverable honest states.

### T056 — Qualify the repair release

**Needs:** T055, T049. **Work area:** integrated plan/apply scenario and compatibility record.

1. Run audit → checkbox selection → approval → preflight → repair → verification using fixtures with stale input, 429 and lost response.
2. Verify two-user isolation and full/readonly API enforcement across plans/events/results.
3. Qualify live writes only on a supported NetBox version and explicitly authorized test objects. Record unavailable external qualification separately.

**Check:** no unselected change occurs, duplicate submissions remain bounded, and all claimed repairs are read-back verified. G is not complete merely because PATCH returned 200.

## H. Cabling and XLSX

Read architecture sections 9 and 15; profile design section 6.

### T057 — Build cabling-policy forms and rack adjacency

**Needs:** T026, T021. **Work area:** `internal/cabling`, policy profile and editor.

1. Add switch filters/explicit selection, speed/media/port-role restrictions, fabric groups and distinct-switch constraints.
2. Add explicit rack adjacency/ranking controls; same-rack preference cannot override hard redundancy constraints.
3. Mark direct topology as supported; show existing patch-panel/breakout paths without offering unimplemented rearrangements.

**Check:** policy can be authored in forms, same-location fallback is explicit, and rack names/IDs are not used as invented physical distances.

### T058 — Find and explain candidate assignments

**Needs:** T057, T022. **Work area:** pure candidate/matching logic and preview table.

1. Exclude occupied, marked-connected, locally reserved, wrong-role/speed/media, logical and unsupported breakout ports.
2. Enforce fabric/switch constraints and valid bond topology; choose deterministic batch assignments with bounded backtracking/matching.
3. Display selected candidates, ranking reason and rejected alternatives. Unsatisfiable requirements stay explicit.

**Check:** a greedy trap fixture still finds a valid pair; incompatible topology fails; same rack wins only among eligible candidates.

### T059 — Reserve endpoints and create planned cables

**Needs:** T058, T052, T055. **Work area:** reservation tables, cable action adapter and review UI.

1. Reserve endpoints transactionally with unique keys, owner and expiry; renew running work and re-acquire/revalidate stale drafts.
2. Compile cable proposals into reviewed actions; immediately re-read both endpoints and occupancy before creating NetBox planned cables.
3. Retain reservations on uncertain writes until reconciliation; expose abandoned planned cables for explicit cleanup.

**Check:** two operators cannot reserve one port in Forge; external NetBox occupancy invalidates apply; reservation expiry never silently deletes an external cable.

### T060 — Track technician work and observed links

**Needs:** T059, T046. **Work area:** cabling work list, confirmation evidence and status transitions.

1. Track proposal/documented/physical-confirmation/observed-peer facts independently, including actor/time/evidence.
2. Add a manual technician confirmation action and approved status updates where appropriate.
3. Accept normalized timestamped neighbor evidence when available; keep no LLDP/unknown peer distinct from a matching link.

**Check:** cable creation alone never marks physical verification complete, and stale peer observation cannot authorize rewiring.

### T061 — Produce authorized XLSX snapshots

**Needs:** T060, T047, T022. **Work area:** `internal/exports`, export jobs/files and download API/UI.

1. Generate Servers, Interfaces, Cabling, Findings and Manifest sheets from a frozen authorized selection; define interface/address row expansion explicitly.
2. Preserve identifiers/IP/MAC/serial as text, write formula-like inputs literally, set headers/filters/widths and record source timestamps/hashes.
3. Recheck current visibility at download, expire exports and exclude credentials/raw sensitive payloads. Readonly may export authorized data.

**Check:** reopen generated workbook with an independent reader; row counts/values/types match fixtures, hostile formula strings stay literal, and user B cannot download A-only rows.

### T062 — Demonstrate the first substantial release

**Needs:** T061, T056. **Work area:** integrated acceptance scenario, usage instructions and ledger.

1. Demonstrate login → selection → connection recipe → inspect → BIOS capture → allocation import → audit → approved repair → cable work list → XLSX.
2. Run restart/readonly/revocation and stale-plan scenarios across the complete flow; verify profiles need no raw text authoring.
3. Document actual supported NetBox/vendor fixtures versus live qualification and remaining installation work.

**Check:** H milestone combined build/test checks pass, with a usable frontend backed by real services/storage. Missing physical qualification remains listed, not hidden behind successful simulations.

## I. Ubuntu and Rocky installation

Read architecture sections 10–11 and profile design sections 5, 7–8. Use an explicitly configured Linux builder/VM environment for image work. macOS can run development/mocks; it is not evidence of a boot-tested Linux installer. Developing an executor does not authorize production disk writes.

### T063 — Catalog and store immutable artifacts

**Needs:** T009, T011, T022. **Work area:** `internal/artifacts`, artifact tables and local store.

1. Add bounded upload/import, checksum verification, immutable file placement and metadata for images/files/scripts.
2. Store large content on disk, metadata/digests in the DB; separate environment access and creator provenance.
3. Add OS/release/architecture/firmware/qualification fields and image catalog UI. Require explicit expected digest/source for imported base media.

**Check:** digest mismatch, partial upload, disk full, path traversal and unauthorized download fail safely; failed writes do not leave a catalog entry claiming a complete artifact.

### T064 — Serve scoped BMC artifact grants

**Needs:** T063, T009. **Work area:** artifact delivery handler and grant lifecycle.

1. Create random deployment/artifact-scoped grants with expiry/revocation; keep browser authentication separate.
2. Support HEAD, Range and repeated GET requests without consuming a token on first access.
3. Use explicitly configured BMC-reachable advertised URLs; redact grant URLs and cap transfer concurrency.

**Check:** repeated/ranged reads reconstruct correct content, cross-artifact grants fail, expired/revoked grants stop access, and log URLs do not reveal tokens.

### T065 — Resolve exact storage targets

**Needs:** T036, T025. **Work area:** storage profile domain and disk selector.

1. Select disks using stable WWN/serial/controller-slot evidence and typed count/capacity/media requirements.
2. Resolve concrete targets for each server; distinguish physical disks and controller virtual volumes.
3. Reject ambiguous/missing identities, install media and unapproved external LUNs; include explicit preserve/wipe scope.

**Check:** disk enumeration reorder does not change identity; extra/missing matches block; an unrelated data disk remains excluded. Never default to `/dev/sda` or the first device.

### T066 — Build supported storage layout forms

**Needs:** T065, T026. **Work area:** storage editor and layout validator.

1. Add inspect-only, single-disk and two-disk software-mirror/LVM templates; unsupported hardware RAID mutation is visibly unavailable.
2. Expose supported GPT/ESP/boot/root/swap/data sizes, filesystem/mounts and volume-group controls with a disk-to-volume preview.
3. Validate sizes/remaining space and show per-renderer support, including bootloader targets and ESP handling for mirrors.

**Check:** a valid mirrored intent resolves into concrete targets/layout; insufficient space and unsupported combinations fail before any builder/action runs.

### T067 — Build installation profile controls

**Needs:** T063, T066, T048. **Work area:** installation wizard and typed profile.

1. Add qualified image/release/architecture, transport and network/storage revision pickers.
2. Add user/key-set, packages, file destinations/modes, hook phase/interpreter/deadline and readiness selectors.
3. Persist and preview through forms. Keep unsupported renderer options disabled with a reason; no default `latest` image or implicit PXE fallback.

**Check:** save/reopen/publish a draft configuration; missing image/keys/profile references surface as fields. Publishing cannot start a deployment.

### T068 — Freeze a deployment specification

**Needs:** T067, T050, T065. **Work area:** `internal/provisioning`, canonical spec and deployment-plan compiler.

1. Combine selected server identity, network/storage graph, image digest, users/files/hooks and readiness into typed immutable input.
2. Separate bootstrap network from final network; validate dependencies needed before configuration retrieval.
3. Include exact disk wipe targets, content/profile hashes and required disruptive actions in a separately reviewed install plan.

**Check:** disk/NIC/image/hook changes invalidate approval; missing capabilities block compilation; a NetBox repair approval cannot authorize installation.

### T069 — Define and sandbox the Linux builder

**Needs:** T063, T068. **Work area:** `cmd/forge-builder`, build request/result contract and runner.

1. Define a versioned build request containing scoped input artifact references/spec hash and a result manifest/digest.
2. Run with pinned tools, isolated workspace, quotas/deadlines and no BMC/NetBox credentials or controller runtime socket.
3. Treat uploaded scripts as data to package, not programs to execute on the builder; clean failed work directories safely.

**Check:** a harmless fixture build succeeds, crash/timeout/disk-full returns a failed job, and untrusted paths cannot escape the workspace.

### T070 — Render minimal Ubuntu autoinstall

**Needs:** T069. **Work area:** Ubuntu renderer and golden fixtures.

1. Select/pin an operator-approved Ubuntu release and obtain its matching official installer schema/reference; record what is verified.
2. Render basic identity, locale/keyboard/time settings, install source and an explicit supported single-disk specification from typed input.
3. Reject unknown/unsupported options and validate the rendered configuration with the matching available tooling.

**Check:** deterministic render and schema validation succeed; output is an installer artifact, not a user-edited profile format. Real media unavailable means qualification is blocked, not guessed.

### T071 — Render Ubuntu networking

**Needs:** T070, T044. **Work area:** Ubuntu bootstrap/final network renderer.

1. Bind physical NICs by verified identity and render supported static addresses, bond/VLAN/bridge nodes, routes, DNS and MTUs.
2. Preserve explicit NetBox VRF versus Linux VRF semantics and handle multiple address families deliberately.
3. Validate that installer networking can be established from embedded configuration without fetching itself first.

**Check:** golden cases for simple static, dual-uplink bond/two VLANs and ambiguous mapping; unsupported graph shapes fail rather than being omitted. VM proof comes later.

### T072 — Render Ubuntu software RAID/LVM and identity guards

**Needs:** T070, T066. **Work area:** Ubuntu storage renderer and pre-write guards.

1. Expand tested single-disk/mirrored templates into concrete partitions, mdraid/LVM/filesystems and preservation rules.
2. Add pre-write host/disk identity validation that aborts before storage mutation; resolve runtime disk names from approved identities.
3. Implement supported mirrored boot/ESP handling and record qualification requirements, without claiming degraded-boot success yet.

**Check:** wrong host/disk identity triggers a guard failure in a test environment; output preserves non-target disks and has consistent capacity arithmetic.

### T073 — Render Ubuntu users, files and hooks

**Needs:** T070, T067. **Work area:** Ubuntu content renderer and hook runner contract.

1. Render users/groups/SSH public keys and login policy without embedding durable controller/private credentials.
2. Package approved files with destination/owner/mode and hook content hashes with explicit phase/interpreter/deadline.
3. Record hook outcomes and retry semantics; validate destinations/input escaping and do not run hooks during render/build.

**Check:** file modes, literal special characters, user groups, hook timeout/result reporting and redaction fixtures pass. A non-idempotent hook is not automatically retried.

### T074 — Build a bootable customized Ubuntu ISO

**Needs:** T071, T072, T073. **Work area:** Linux ISO builder adapter and output validation.

1. Embed generated configuration/content into the selected base ISO; patch its correct boot entries for unattended use.
2. Preserve the qualified firmware boot metadata and prefer a single virtual-media ISO; do not require a second seed slot.
3. Record base digest, tool/renderer versions, input manifest and output checksum; verify the ISO's expected files and boot structure.

**Check:** content/boot inspection and checksum pass. This is artifact validation only; mark installation support unqualified until VM tests.

### T075 — Enroll installer progress securely

**Needs:** T064, T068, T015. **Work area:** deployment enrollment/progress API and installer helper.

1. Issue a short-lived bootstrap grant bound to server/deployment/manifest; exchange once for narrow progress access.
2. Record authenticated sequence/idempotency-checked events and newly generated host key/identity for later verification.
3. Add callback emission to the installer content; keep progress rights separate from hardware/control permissions.

**Check:** replay, wrong deployment/manifest, expired grants and unordered duplicate events are handled correctly; a completion callback alone never marks the host ready.

### T076 — Verify host readiness over SSH

**Needs:** T075, T068. **Work area:** SSH adapter, verifier and readiness connection forms.

1. Use enrolled/operator-verified host keys and scoped SSH credentials; reject insecure automatic key acceptance.
2. Compare actual serial/UUID and current deployment marker, then OS, network, storage and configured service/hook results.
3. Return structured evidence per check and allow independent verification retry without reinstalling.

**Check:** an old OS answering at the reused IP fails identity/deployment checks; wrong host key fails; timeout does not trigger a disk rewrite.

### T077 — Control virtual media safely

**Needs:** T034, T064, T014. **Work area:** media driver capability/read/mount/eject operations.

1. Discover media resources/actions/protocols and enforce qualified capabilities; preserve operation/session references.
2. Implement mount/read-back/eject through approved step requests, including asynchronous task observation.
3. Keep session lifetime policies explicit; do not automatically close a session that may own attached media.

**Check:** fixture tests cover already-mounted correct/wrong media, lost mount response, long task, session expiry and unsupported protocol. No direct UI bypass of approval.

### T078 — Control one-time boot and power

**Needs:** T077, T014. **Work area:** boot/power capability adapters and task observation.

1. Read supported boot targets/modes and current power state; construct explicit one-time boot changes.
2. Dispatch only approved power intent and persist uncertain effects/remote references.
3. Verify subsequent state; reject unsupported power/boot combinations and avoid blind reset retries.

**Check:** a response-lost reset is reconciled, not repeated; persistent boot order is not silently rewritten; read-only inspection paths cannot invoke these operations.

### T079 — Execute the deployment sequence

**Needs:** T074–T078, T052. **Work area:** deployment workflow service and persistent steps.

1. Execute approved preflight → build/validate → mount → boot-once → power → observe installer → safe media/local-boot cleanup → readiness.
2. Recheck actor/credential/identity at applicable boundaries, persist remote task IDs, and maintain artifact grants through the required media lifetime.
3. Distinguish succeeded, failed, waiting, uncertain and cleanup-needed; use per-server locks/canary batch limits.

**Check:** full fixture workflow succeeds only after readiness and required cleanup; a restart at every dispatch/result boundary cannot silently duplicate a destructive effect.

### T080 — Handle interrupted installation and cancellation

**Needs:** T079. **Work area:** recovery handlers and operator job controls.

1. Define resume/reconcile behavior for build, media, boot, installation, cleanup and readiness separately.
2. Cancel future work safely; when the installer is writing disks, keep monitoring and do not power off as a generic cancellation mechanism.
3. Show explicit operator actions for uncertain effects and independent retry of readiness/cleanup.

**Check:** controller restart, lost callback, credential revoke, artifact expiry and cancellation during writing produce safe truthful status. No “rollback complete” message without an actual reversible operation.

### T081 — Install Ubuntu in a disposable VM

**Needs:** T079, T080. **Work area:** Linux VM harness and qualification artifacts.

1. Boot the generated ISO in an explicitly disposable UEFI VM with fixture identities, a target disk and a non-target data disk.
2. Complete single-disk installation without PXE; inspect final OS identity, networking, user/key/file/hook behavior and readiness.
3. Preserve install logs and verifier evidence; ensure wrong-identity runs abort before modifying disks.

**Check:** installed-system evidence, not merely a boot screen or successful ISO build. If VM tooling/image is unavailable, record the blocker and continue independent cards.

### T082 — Qualify Ubuntu network/storage variants

**Needs:** T081. **Work area:** VM scenarios for two NICs, VLAN/bond and multiple disks.

1. Test supported bond/VLAN/static bootstrap and final networking; inspect routes/MTU/address ownership from the OS.
2. Test mdraid/LVM/mount layout and preservation of unrelated disks.
3. Remove one mirrored boot member in disposable tests and verify degraded boot/ESP behavior; fix renderer or mark layout unsupported until it passes.

**Check:** every advertised layout has resulting-OS and failure-case evidence. Do not claim resilient mirroring from an mdraid configuration file alone.

### T083 — Render a pinned Rocky installer baseline

**Needs:** T069, T068. **Work area:** Rocky Kickstart renderer and capability registration.

1. Select/pin an operator-approved Rocky release/image and matching installer tooling/reference.
2. Render/validate basic installer identity, sources, users/login defaults and supported single-disk baseline.
3. Add separate Rocky renderer identity/version and explicit unsupported feature errors; do not alias it to Ubuntu.

**Check:** deterministic valid Kickstart baseline and release checks. Missing real media remains an external qualification dependency.

### T084 — Render Rocky networking

**Needs:** T083, T041. **Work area:** Rocky bootstrap/target network renderer.

1. Translate supported physical bindings/bonds/VLANs/routes/DNS/MTU into the qualified installer and target NetworkManager configuration.
2. Ensure the earliest required bootstrap networking is available without circular retrieval.
3. Compare semantic output against the same canonical spec cases used for Ubuntu; preserve IPv4/IPv6/VRF distinctions.

**Check:** supported static/bond/VLAN fixtures and missing mapping failure. Copying Ubuntu netplan output is not acceptable Rocky support.

### T085 — Render Rocky storage and content

**Needs:** T083, T066, T073. **Work area:** Rocky storage/content renderers and pre-write guard.

1. Implement exact disk guards and supported partition/mdraid/LVM/ESP layouts; validate bootloader targets and preserved disks.
2. Render distro-appropriate users/groups, file modes/contexts and hook stages/results, including relevant SELinux behavior.
3. Package enrollment/readiness helpers from shared contracts while retaining Rocky-specific installer semantics.

**Check:** golden/schema/guard tests cover storage and content separately. If this card exceeds context, split into `T085a` storage and `T085b` content and finish both before T086.

### T086 — Build and install Rocky in VMs

**Needs:** T084, T085, T075, T076. **Work area:** Rocky remaster adapter and VM qualification scenarios.

1. Remaster the pinned ISO while preserving its boot metadata and embedded configuration delivery.
2. Run single-disk then advertised network/mirrored-storage scenarios; inspect final OS/network/storage/content and callback/SSH identity.
3. Exercise failed guards and degraded boot; compare against the Ubuntu acceptance matrix rather than assuming identical behavior.

**Check:** actual Rocky installed-system evidence exists for each claimed layout. Split remaster/VM scenarios into ledger subtasks if necessary; neither can be skipped.

### T087 — Capture vendor-specific qualification prerequisites

**Needs:** T040, T077, T078. **Work area:** compatibility matrix and sanitized vendor fixtures.

1. Identify exact authorized lab Gigabyte/Lenovo/Yadro model/SKU/BMC/BIOS/firmware/license versions and reachable media endpoint.
2. Perform scoped read-only discovery and compare available actions/registry behavior with generic adapter assumptions.
3. Implement only necessary narrowly selected adapter differences, with fixtures; leave unavailable vendor rows unqualified.

**Check:** every proposed destructive lab test has concrete target identity and supported capability evidence; a generic vendor label is not a qualification result.

### T088 — Qualify real virtual-media deployment behavior

**Needs:** T087, T081 or T086. **Work area:** explicitly approved lab runs and vendor adapter regression cases.

1. On designated lab targets, test media attach/read-back, one-time boot, approved reset and complete installation.
2. Test media retention through long operations/session expiry, final reboot/eject/local boot and controlled recovery.
3. Record exact model/firmware/OS/layout combinations and failures; do not generalize one Lenovo generation to all Lenovo servers.

**Check:** live support claims are backed by run IDs/evidence. This card is blocked externally for unavailable/unauthorized lab hardware; do not substitute a production host.

### T089 — Finish the operator deployment UI

**Needs:** T079, T080, T067. **Work area:** install preview/approval and live deployment screens.

1. Show exact host/disk identity, resolved network/storage, image/hook hashes, capability gaps and disruptive sequence before approval.
2. Present real step/events, waiting reasons, pending cancellation and separate retry-readiness/cleanup actions.
3. Distinguish VM-tested, physical-qualified and unqualified combinations in the image/target selection flow.

**Check:** full UI-to-backend approval path works and readonly direct calls remain forbidden; unqualified combinations are never labelled verified merely because a renderer exists.

### T090 — Close the provisioning milestone

**Needs:** T082, T086, T089; T088 for each claimed physical path. **Work area:** end-to-end acceptance report and ledger.

1. Repeat the architecture's integrated scenario with real Ubuntu/Rocky VM outputs and all prerequisite audit/repair/cabling behavior.
2. Run restart, stale plan, wrong host, credential revoke and uncertain-operation failure cases.
3. Publish a precise support matrix and remaining hardware blockers; distinguish implemented code from qualified deployment paths.

**Check:** I's advertised provisioning combinations pass their gates. Missing hardware qualification does not erase completed code, but prevents declaring that hardware path supported.

## J. Identity integration, PostgreSQL and operations

Read architecture sections 12–13, 16. These are required planned capabilities, not an excuse to replace per-user NetBox keys with a service account.

### T091 — Authenticate against FreeIPA

**Needs:** T006, T008, T009. **Work area:** FreeIPA provider and authentication settings.

1. Configure verified LDAPS/StartTLS, bounded search using an appropriately scoped service credential and escaped filters.
2. Authenticate the resolved user without retaining their password; obtain provider plus immutable directory identity.
3. Add provider selection/configuration and diagnostics with redacted failures; keep local recovery explicit.

**Check:** invalid credentials, invalid CA, injection-like username, search ambiguity and timeout fail correctly. A test double is not proof of the real realm's MFA/trust policy.

### T092 — Map FreeIPA groups and existing accounts

**Needs:** T091. **Work area:** group-role mapping, deliberate account-linking and session invalidation.

1. Configure exact full/readonly group mappings, precedence and nested-group behavior; deny unmapped users.
2. Link an existing local user through an explicit authorized operation, never by similar email/name alone.
3. Invalidate or bound role/session caches on disable/group change; retain separate user-owned NetBox credentials and scope.

**Check:** rename preserves identity, group removal prevents subsequent mutation, and linked users keep the correct keys. Qualify real FreeIPA behavior when credentials are available.

### T093 — Implement PostgreSQL repositories

**Needs:** T062; T090 before claiming complete provisioning parity. **Work area:** `internal/store/postgres`, dialect migrations and repository tests.

1. Implement existing repository contracts using explicit PostgreSQL queries/migrations and the same IDs/time semantics.
2. Port transactional claims/reservations and enforce the same uniqueness/foreign keys.
3. Run a shared conformance suite for every implemented aggregate on both databases; keep one executor until multiprocess semantics are separately qualified.

**Check:** inventory/profile/job/approval/secret/deployment behavior matches SQLite. A successful connection and a changed DSN are not PostgreSQL support.

### T094 — Migrate existing SQLite state

**Needs:** T093. **Work area:** migration command and verification report.

1. Freeze mutations and export/import stable IDs, references, revisions, timestamps, encrypted secret key IDs and audit history.
2. Transfer/verify artifact references separately; preserve required files and external encryption keys.
3. Compare row counts, referential integrity and representative content/digests before allowing cutover; document restoration path.

**Check:** migrated snapshots/plans/jobs remain readable with identical identities, and active/uncertain jobs do not auto-replay on first PostgreSQL start.

### T095 — Back up and restore consistently

**Needs:** T063, T014, T005. **Work area:** backup/restore tooling and isolated restore test.

1. Back up SQLite with a consistent method accounting for WAL, plus required artifact manifests/files; document PostgreSQL backup when available.
2. Keep key backup/restore separate and test missing-key failure clearly.
3. Restore into execution-disabled mode, verify content, then reconcile unfinished jobs before mutation can be enabled.

**Check:** restored inventory/profiles/approvals/artifacts decrypt/read correctly; uncertain external jobs cannot be replayed just because the DB was restored.

### T096 — Enforce retention and capacity limits

**Needs:** T095, T061. **Work area:** garbage collection, quotas and maintenance UI/jobs.

1. Apply configurable retention to raw observations, normalized history, logs, exports and generated ISOs using the architecture defaults as proposals.
2. Preserve records referenced by active/retained approvals and artifacts mounted or needed by a running deployment.
3. Report reclaimable space, quota pressure and cleanup failures; make cleanup idempotent and path-safe.

**Check:** expired unreferenced files are removed, active/pinned files remain, partial cleanup/restart is safe and disk-full errors do not corrupt records.

### T097 — Add operational metrics and diagnostics

**Needs:** T020, T079, T096. **Work area:** metrics, health/readiness and settings/diagnostics UI.

1. Expose queue age/depth, NetBox latency/cooldown/429, BMC failures, observation age, build/install stages and artifact disk/transfer status.
2. Separate process liveness, local readiness and remote dependency degradation.
3. Use bounded labels and redacted logs; link correlation IDs to authorized job evidence.

**Check:** injected NetBox failure does not falsely report local process death; no secrets/grant URLs appear in metrics or diagnostic bundles.

### T098 — Measure supported workload sizes

**Needs:** T097, T062. **Work area:** local synthetic load scenarios and measured results.

1. Use the architecture's proposed dataset sizes with paginated views and bounded inspection/build/deployment pools.
2. Measure request count, latency, memory, queue wait, SQLite contention and export size; tune from evidence.
3. Verify host fairness/cooldown and responsiveness under a large audit. Record actual environment and results rather than promising unmeasured throughput.

**Check:** configured bounds hold without request storms or unbounded memory growth; identified bottlenecks have concrete limitations or fixes.

### T099 — Run cross-cutting authorization and recovery checks

**Needs:** T090, T092, T093, T095. **Work area:** integrated regression scenarios.

1. Test narrower-user visibility on inventory/findings/plans/events/artifacts/exports and revocation during queued/running workflows.
2. Test tampered inputs, endpoint/redirect restrictions, secret masking, callback replay and stale/changed deployment approval.
3. Repeat uncertain-effect recovery on both databases and supported auth providers. Fix findings before release claims.

**Check:** every backend route enforces its intended actor/scope; no remote destructive replay occurs solely from a lease timeout or restore.

### T100 — Publish operating instructions and release status

**Needs:** T094, T096–T099; external gates must be stated honestly. **Work area:** operations/usage docs, compatibility matrix and ledger.

1. Document install/configuration, named-user/bootstrap recovery, FreeIPA mapping, NetBox keys, profile workflow, builder/network paths and supported combinations.
2. Add runbooks for 429, credential rotation, BIOS registry drift, stale planned cables, lost media session, failed readiness, uncertain jobs and restore.
3. Record completed task IDs, exact check evidence and remaining unqualified hardware/extensions. Link actual runnable commands and examples.

**Check:** a new operator can run the claimed release from documented steps; no future feature or unrun lab test is represented as completed.

## Optional extension cards

Implement only the extension being worked on, using the same small-card discipline. These cards define complete outcomes; split their numbered steps into ledger subtasks before coding if needed. Windows remains explicitly outside the first iteration. The architecture's extension scope is preserved.

### E001 — QCOW2 through a deploy ISO

**Needs:** T090; read architecture section 10.3.

1. Define a supported-image contract; inspect in an isolated builder, reject external backing/data files, verify architecture/virtual size/sector/boot assumptions and flatten deliberately.
2. Build an ephemeral deploy ISO with authenticated manifest retrieval and pre-write host/disk guards.
3. Write logical raw disk contents correctly, including zeros in source holes on a used disk; never copy QCOW2 container bytes directly.
4. Implement supported per-host identity/config injection, GPT/growth/boot repairs and final readiness. Initially reject arbitrary RAID/LVM transforms of whole-disk images.

**Check:** disposable VM with prefilled nonzero target, wrong target identity, truncated image and reused host identity tests; full boot/readiness evidence. No “image downloaded” success shortcut.

### E002 — Hardware RAID mutation

**Needs:** T088 for the controller family, T065, T079.

1. Add controller-specific plan/apply/task discovery with concrete drives and destructive impact.
2. Apply only separately approved changes and reconcile pending jobs/resets.
3. Reinspect resulting virtual volumes and generate a new OS-target plan when concrete targets change.

**Check:** lab-qualified controller/firmware behavior, response-lost recovery and explicit approval of newly resolved targets. Generic Redfish schema presence is insufficient qualification.

### E003 — BIOS mutation from a baseline

**Needs:** T039, T078, T088 for the family.

1. Validate native writable attributes, enum values, dependencies and existing pending settings against the qualified registry.
2. Plan only approved field differences; reject conflicts with unrelated pending settings and stage at the approved apply time.
3. Perform an approved reset if needed, re-read active values and record final compliance.

**Check:** staging does not count as compliance; unrelated pending fields survive; reset-to-defaults/firmware flashing are not used as generic repairs.

### E004 — Read switch LLDP observations

**Needs:** T060, T033.

1. Add a scoped read-only SSH/NETCONF/SNMP adapter for one switch family/protocol.
2. Normalize chassis/port IDs and explicit aliases, retaining source time and confidence.
3. Compare to documented cable paths without changing switch configuration or approving rewiring automatically.

**Check:** stale/missing/ambiguous neighbor evidence stays unknown; only a confirmed identity match counts as the expected peer.

### E005 — Boot a read-only discovery environment

**Needs:** T074, T075, T079.

1. Build an ephemeral inventory ISO for facts BMCs cannot supply, with no persistent host agent requirement.
2. Run it through an explicitly approved disruptive boot plan and authenticated enrollment.
3. Collect NIC/PCI/disk/OS-visible facts without writing target disks, then restore intended boot/media state.

**Check:** before/after disk verification in a lab shows no inventory-induced writes; reboot disruption remains explicit and observations have trustworthy provenance.

### E006 — Add narrow IPMI fallback

**Needs:** T033, T078.

1. Add only qualified inventory/power/boot capabilities with strict argument handling and secret isolation.
2. Reuse common target/profile/capability semantics; unsupported media/RAID remains unsupported.
3. Keep fallback explicit; failed Redfish authentication must not initiate credential guessing across protocols.

**Check:** protocol-specific fixtures and lab observations; no accidental assumption that standard IPMI provides virtual-media installation.

### E007 — Add an explicit PXE/iPXE transport

**Needs:** T090.

1. Reuse the deployment spec, enrollment and readiness contracts with a separately configured boot transport.
2. Define operator-owned DHCP/TFTP/HTTP integration and identity/selection constraints; never enable network services implicitly.
3. Qualify boot/install/cleanup in an isolated network and retain Redfish ISO as the default path.

**Check:** selecting ISO never touches PXE settings, and selecting PXE cannot affect unselected hosts or an unspecified network.

### E008 — Add remote workers or a new OS backend

**Needs:** T100; choose one subproject, not both at once.

1. For remote workers, design authenticated dispatch, scoped secret/artifact access, coordinated request budgets and explicit uncertain-effect reconciliation before implementing transport.
2. For a new OS, add a separate renderer/verifier and profile controls with concrete image/driver/boot prerequisites; Windows needs its own unattended install and qualification path.
3. Preserve existing workflows and run shared contract tests plus the new worker/OS failure matrix.

**Check:** do not claim multi-executor HA without partition/revocation/replay tests; do not claim new OS support from a dropdown or generated config alone.

## Session prompts and stopping rules

Use this prompt to start an implementation session:

> Read the introduction and milestone map in `docs/small-agent-plan.md`, then `docs/implementation-status.md` if it exists. Inspect the actual repository state. Implement the next ready task card, reading only its relevant architecture/profile sections and code. Complete the card's behavioral checks, update the ledger with actual evidence and the next task ID, then continue ready cards if the session allows. Preserve form-based profiles, per-user NetBox authorization, static/derived BMC credentials and model-compatible BIOS baselines. Do not claim unrun hardware tests or replace required behavior with mock success. Do not start live destructive work without an authorized designated target and concrete approved plan.

Use this prompt when resuming a particular task:

> Resume task `<ID>` from `docs/small-agent-plan.md`. First verify its prerequisites and unfinished changes from the ledger; do not redo completed tasks. Implement only the remaining slice, run the listed checks, and record results and next steps. If an external dependency blocks qualification, state exactly which input/evidence is missing and continue an independent ready task.

Pause dependent work when target identity is ambiguous, an operation may already have happened, required source/version/secret data is missing, or a planned action exceeds existing authorization. These conditions do not prevent local code, fixture tests, documentation or independent tasks. Do not repeatedly ask the same question or turn every task boundary into an approval request.

Before ending any session, the ledger must answer: **what works, what proves it, what is unfinished, and which exact task comes next?**
