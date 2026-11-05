# Implementation handoff

**Updated workspace decision:** Use one shared workspace and one list of users and profiles; older environment-selection and membership requirements in this document are superseded. Per-user NetBox credentials and actor-scoped evidence remain required.

Read [architecture](architecture.md) and [profile editor design](profile-design.md) before coding. This repository currently contains design documents only. The user intends to switch to Terra for implementation; this handoff does not change the model or start implementation.

## 1. Requirements that must survive implementation shortcuts

1. Go backend; Svelte 5 + TypeScript frontend; use the real Mineral package at `/Users/danil/Development/mineral`.
2. Profiles are usable structured forms/builders from the MVP. No Kubernetes-style manifest authoring and no YAML/JSON profile-editor substitute.
3. SQLite first, repository boundary for a real later PostgreSQL implementation.
4. NetBox is the inventory authority; filters freeze explicit selected IDs. Audit and job results stay in Forge.
5. Two roles, full and readonly; named local users after environment-token bootstrap; later FreeIPA; a unique NetBox credential per user.
6. Hardware observations, including available BIOS settings/registry/pending data, are cached with provenance, completeness and age.
7. Connection profiles support static passwords and derived passwords. The primary derived recipe is optional secret prefix + last octet of the actual BMC IPv4 + optional secret suffix, with explicit padding. Additional declared NetBox-serial transforms are supported through typed controls, not scripting.
8. BIOS profiles are capturable from a reference host, immutable when published, and scoped to compatible vendor/model/firmware/registry variants. Do not blindly compare/copy settings across vendors.
9. Every external change has a concrete approved plan and verification. Audits and profile publication never silently mutate hardware or NetBox.
10. Kayobe-style allocation maps are imported as data; extra hosts do not enlarge the selection.
11. Handle 429 with shared rate limiting, `Retry-After`, jitter and deferred retries; debouncing alone is insufficient.
12. Cabling means candidate selection, approved NetBox records, technician work and observed verification as separate states.
13. Ubuntu and Rocky use customized ISO installation over Redfish virtual media first. No default PXE dependency.
14. Software RAID/LVM, network config, users, SSH keys, files and hooks have real distro renderers and resulting-OS verification.
15. QCOW2 deploy ISO, hardware RAID mutation, BIOS mutation, IPMI fallback, PXE/iPXE and Windows are explicit extensions; unsupported features cannot be presented as working.
16. Cabling/interfaces XLSX export is part of the audit/cabling release.

## 2. Work discipline

Implement vertical slices with a usable UI, API, persistence and tests. Do not build an attractive dashboard backed only by mocks and call the application complete. Mocks are required for deterministic development, but the UI and qualification report must clearly distinguish simulation from live operation.

Use fixtures and local simulators when external credentials/hardware are unavailable. Continue unrelated work; list exact blocked qualification steps. Do not invent the NetBox version or vendor capabilities. Live destructive operations require a designated lab target and a concrete reviewed plan; implementing support does not itself authorize wiping production servers.

Keep an implementation ledger in `docs/implementation-status.md`: completed phase, changed contracts, tests run, actual results, known limitations and next work. If the session is interrupted, update that ledger so the next agent can resume without repeating discovery. Add architecture decision records only when a material design choice changes.

Prefer ordinary typed code over a general workflow DSL, expression language or schema-driven UI framework. Shared form primitives are useful; category-specific editors remain explicit. Use maintained dependencies and pin versions. Do not modify Mineral wholesale; adapt its exported components and fix only a concrete missing behavior if required.

## 3. Phase 0 — Establish the project and compatibility targets

Steps:

1. Inspect the repository and any applicable instructions. Preserve user work. Confirm the empty-app starting point and the different `Develpoment/forge` versus `Development/mineral` paths.
2. Inspect installed Go/Node tooling and Mineral exports/peer requirements. Select and pin compatible versions. Record dependency choices; do not blindly use versions copied from an unrelated application.
3. Create the Go module, SPA build, Makefile/task scripts, formatting/linting, test commands and configuration loading.
4. Build one Go binary serving `/api/v1`, health endpoints and embedded frontend assets. Add graceful shutdown and structured redacted logging.
5. Add a local development mode with deterministic fake NetBox/BMC fixtures and explicit simulation branding.
6. Create the compatibility matrix document with columns: vendor, model/SKU, BMC generation/version, BIOS version, Redfish version, inventory coverage, BIOS registry, media method/session behavior, boot/power, RAID and qualification evidence. Add Gigabyte/Lenovo/Yadro rows with unknown fields, not invented support.
7. Pin Mineral for reproducible CI using a generated package archive or a reproducible repository source. Local development can use the absolute path; builds elsewhere cannot depend on it being present.

Done when: the frontend renders real Mineral controls, the backend serves them, health/config work, tests run, and a clean checkout/build path is documented. No live infrastructure access is needed.

## 4. Phase 1 — Persistence, identity and job skeleton

Steps:

1. Define core domain IDs, errors and repository interfaces. Add SQLite migrations for users/sessions, environments, credentials, servers, jobs/steps/events, artifacts and audit events. Add later tables with their feature phase.
2. Configure foreign keys, WAL, busy timeout and bounded writer behavior on all appropriate connections. Add migrations/backup hooks and transactional tests.
3. Implement first-run `FORGE_BOOTSTRAP_TOKEN` setup, a separate encryption key, named local user/token issuance and full/readonly enforcement.
4. Implement sessions, logout/revocation, CSRF, secure cookies, rate-limited login and secret redaction. Store local token hashes; encrypt recoverable NetBox/BMC credentials.
5. Build a durable job claim loop with short transactions, retries scheduled by timestamp, monotonic events, one-process executor lock and per-resource leases. Start with a harmless simulated multistep job.
6. Add job status and SSE UI with reconnect/replay and authorization filtering.

Done when: restart resumes harmless steps without duplicating completed work, a duplicate API idempotency key returns the same job, and readonly users cannot invoke operational routes even by direct HTTP calls.

Tests: simultaneous claims, stale lease, process restart, role change, expired session, secret absence in logs/events/errors and SSE reconnection.

## 5. Phase 2 — Per-user NetBox inventory

Steps:

1. Build own-credential add/test/rotate/delete UI. Never return the token from read endpoints. Associate a credential generation with jobs and caches.
2. Implement compatibility discovery and a read-only report. Start with sanitized representative fixtures; obtain the actual deployed API version before enabling live writes.
3. Implement the HTTP transport: shared host budget/cooldown, per-user fairness, bounded response size/pagination, cancellation and timeouts. Retry safe reads with `Retry-After` support.
4. Fetch filtered devices and bounded related objects; translate version-specific DTOs into stable domain types. Keep source payload/hash/completeness and per-user cache scope.
5. Create the server registry and explicit frozen selections. Handle rename, missing permission, incomplete pagination and confirmed deletion distinctly.
6. Build inventory filtering, paging, bulk selection and server detail. Show freshness and unavailable evidence. Add visibility checks to every derived resource route.

Done when: selecting ten devices fetches only scoped data/dependencies, the UI uses local snapshots, credentials stay user-specific, and 429 does not cause a retry storm.

Tests: pagination boundaries, duplicate names, renamed device, revoked token, 403 versus deletion, repeated queries coalesced only for the same user/generation, two users with different object visibility, 429 seconds/date/missing header and partial snapshot failure.

## 6. Phase 3 — Profile forms and credentials

Steps:

1. Add typed internal profile contracts, draft/published revisions, references, assignments and schema-version migrations. Validate on the backend.
2. Build the shared profile list/editor shell, applicability selectors, priority/conflict preview, draft save/publish and immutable revision history.
3. Implement connection forms first: endpoint source, driver, TLS, system selector and credentials.
4. Implement static password storage and the prefix/value/suffix credential form. Resolve management IP once and pass that exact canonical address to both derivation and transport. Preserve TLS name separately when required.
5. Add typed serial substring/case/padding recipe segments, masked previews and bounded “Test connection.” Resolve only pre-login data sources.
6. Add the hardware-rule editor, then network graph editor and storage/cabling/installation forms incrementally with their corresponding phases. Do not expose unimplemented controls as functional.
7. Implement deterministic profile resolution, explicit revision pinning, per-server bindings and affected-server preview. Never execute arbitrary template code to resolve profiles.

Done when: an operator can create and test a connection profile without editing source/config text, publish it, preview its selected servers, and inspect masked derivation for an example BMC.

Tests: static passwords; prefix-only/suffix-only/both; `.7 → 7` and `.7 → 007`; `.0`/`.255`; invalid IP/IPv6/URL input; ambiguous DNS; wrong data-network IP not substituted; too-short serial; secret redaction; credential/address change invalidates resolution; no guessing after failed authentication; equal-priority match rejected.

## 7. Phase 4 — Redfish inspection and BIOS baseline capture

Steps:

1. Define capability and normalized observation types, including explicit unknown/denied/partial states. Implement a fixture driver before the real adapter.
2. Implement Redfish root/link discovery, system selection, sessions, inventory collection, sanitization and per-BMC throttling. Wrap a library if useful; keep vendor DTOs out of domain services.
3. Collect identity/firmware, CPU/RAM, NICs, disks/controllers/volumes and active BIOS attributes/registry/pending settings where available. Cache with provenance, timestamps and coverage. Do not replace last-good data with empty data on error.
4. Build server hardware and BIOS tabs with NetBox comparisons, current/pending distinction and field-level evidence age.
5. Implement “Create BIOS profile from this host”: capture recent active settings → default exclusions → inclusion checkboxes/typed expected values → applicability constraints → preview → publish.
6. Add multiple explicit model/vendor variants under a named BIOS baseline. Preserve source observation and registry content hashes. Recapture produces a new draft/diff.
7. Add NIC identity binding UI. Support authenticated SSH inspection when needed to establish OS-level facts; model a future discovery ISO as a separate approved disruptive operation.
8. Record sanitized fixtures from actual vendors when available; implement the smallest needed read-only quirks. Firmware-specific facts belong in the compatibility matrix.

Done when: a hardware audit can run entirely from persisted observations, missing evidence stays unknown, and one host's captured BIOS settings can audit compatible peers without comparing incompatible vendors or treating pending settings as active.

Tests: multiple Systems, unsupported resource, incomplete NIC inventory, ambiguous MAC mapping, invalid units, stale last-good snapshot, wrong serial, missing registry, registry content changed under same name, sensitive baseline exclusions, incompatible model, overlapping variants, pending desired/active undesired, source host changes after publication, permission-denied versus unsupported.

## 8. Phase 5 — Network allocation, audit and plan generation

Steps:

1. Complete network forms: physical bindings, bonds, VLAN parents, bridges where supported, MTU, address networks, VRFs, prefixes, routes/DNS and primary-IP rules.
2. Implement bounded allocation-file parsing with duplicate-key rejection and a table mapping groups to network rows. Freeze selection and resolve explicit host aliases.
3. Build pure compliance rules for required fields, identity/hardware, BIOS variants, network graphs/IPAM and documented/observed cabling.
4. Produce findings with expected/actual/evidence, severity and blocking policy. Add safe narrow waivers; never waive wrong server identity or ambiguous destructive disks.
5. Compile actionable findings into typed action DAGs. Separate non-actionable investigation/manual tasks. Create exact field-limited diffs and preconditions.
6. Build audit and plan-review UI with dependency-aware checkbox groups and structured diffs. Store immutable selected-action approvals.

Done when: the worked host1 allocation example generates only host1's intended interfaces/IPs; extra hosts remain ignored; source changes make the plan stale; no audit makes external writes.

Tests: IPv4/IPv6 parsing, missing selected host, extra hosts, duplicate aliases, VRF overlap, same-IP conflict, invalid CIDR, cyclic graph, parent/member constraints, primary-IP dependencies, missing observed NIC coverage, unsupported BIOS variant, deterministic output hashes and checkbox dependency closure.

## 9. Phase 6 — Approved NetBox remediation

Steps:

1. Add typed mutations for missing interfaces, logical relationships, IP creation/assignment and primary IP. Restrict edits to approved fields.
2. Execute approved actions using the initiator's credential and generation. Acquire leases, re-read affected state, recheck permission and preconditions.
3. Use conditional updates for supported releases; document/test best-effort stale protection for releases without them. Keep unqualified write schemas disabled.
4. Persist intent/results and created IDs. Implement reconciliation after ambiguous writes, safe retry boundaries and partial-plan reporting.
5. Re-audit touched objects after apply; display verified success, remaining findings and blocked dependencies.

Done when: approving a subset changes exactly that subset plus visible prerequisites, re-execution is harmless where reconciliation proves it, and uncertain outcomes stop instead of duplicating writes.

Tests: two users editing same object, 412/conflict, POST succeeded but response lost, field changed after approval, bulk failure, read-only NetBox token, rotated/revoked actor credential, server role loss, partial cross-model apply and independent host continuation.

Release gate: audit, forms, BIOS baselines and NetBox remediation are now usable against a tested NetBox version. Do not yet claim installation support.

## 10. Phase 7 — Cabling and XLSX

Steps:

1. Complete cable-policy forms, explicit switch selection and rack-adjacency editing.
2. Implement eligibility filters and deterministic batch candidate assignment with hard failure-domain constraints, explanatory ranking and bounded search.
3. Add transactional endpoint reservations, expiry/renewal, conflict recovery and revalidation immediately before apply.
4. Create approved planned cable records. Track technician confirmation and observed link separately. Show unsupported patch-panel/breakout topology as a manual task.
5. Add XLSX export jobs with Servers/Interfaces/Cabling/Findings/Manifest sheets, stable types/order and safe literal text cells.
6. Apply authorization at export creation and download. Expire files and remove secrets.

Done when: two operators cannot reserve the same port in Forge; external changes are detected at apply; selected cabling/interfaces export accurately; physical completion is not claimed merely because a cable record exists.

Tests: same-rack preference, no eligible same-rack port, adjacency fallback, two-fabric requirement, unsatisfiable batch, external occupied port, expired draft reservation, ambiguous write holds reservation, formula-looking strings, IP/MAC preservation and export visibility revocation.

## 11. Phase 8 — Image artifacts, storage and Ubuntu deployment

Steps:

1. Build artifact catalog/upload/verification and local file storage. Add input/output digest manifests, quotas, retention and scoped repeated/ranged delivery grants.
2. Implement a controlled Linux builder process/container with pinned tools. Avoid exposing a privileged runtime socket to the API. Validate base ISO provenance and preserve boot metadata.
3. Complete storage/install forms and canonical resolved deployment spec. Pin concrete disk identities and renderer support; show exact wipe scope in plan review.
4. Implement one qualified Ubuntu release renderer: embedded autoinstall data, static bootstrap/final networking, supported bonds/VLANs, software RAID/LVM, users/keys, files and hooks. Reject features not supported by the renderer.
5. Add pre-disk-write machine/disk identity guards, authenticated enrollment/progress and independent SSH readiness with pinned host keys.
6. Implement the deployment step engine with fixture media/power/boot controllers and failure injection before touching actual BMCs.
7. Implement actual Redfish media/one-time boot/power/task operations behind capability checks. Verify media mount, session lifetime, reboot/cleanup and local boot.
8. Run a real VM installation from the generated ISO, inspect the installed system, then qualify one explicitly designated physical lab target with a concrete approved deployment.

Done when: an actual Ubuntu installation has the intended network/storage/users/files/hooks, readiness proves this deployment's host identity, and media cleanup/restart behavior is verified. A generated ISO or a mock “success” is insufficient.

Tests: UEFI boot, one virtual-media slot, no-PXE install, static bond/VLAN bootstrap or explicit unsupported rejection, disk-order changes, identity mismatch aborts before writes, non-target disk preserved, mirrored boot failure test, stale host at target IP, tampered/replayed callback, old deployment marker, expired media URL, HEAD/Range/repeated GETs, BMC session expiry, installer timeout and restart during every external-effect boundary.

## 12. Phase 9 — Rocky and vendor qualification

Steps:

1. Choose/pin an actual Rocky release and installer toolchain; implement a separate Kickstart and target-network renderer from the canonical spec.
2. Verify Rocky-specific user groups, NetworkManager configuration, storage/boot behavior, SELinux/file contexts and hook stages rather than reusing Ubuntu shell snippets indiscriminately.
3. Run the same installed-system and failure/recovery acceptance suite on Rocky. Unsupported feature differences must surface before approval.
4. Qualify actual Gigabyte, Lenovo and Yadro model/firmware paths for discovery, BIOS capture, media insertion, tasks, one-time boot, reset and cleanup. Test long installation/media session behavior, not only short API calls.
5. Add vendor overrides only for observed differences, scoped by capability/model/firmware. Include read-only test fixtures and regression cases.

Done when: Ubuntu and Rocky both pass on their supported layouts, and the compatibility matrix distinguishes lab-qualified vendor models from merely supported generic Redfish code. Missing access to a vendor keeps that matrix row unqualified; it does not block unrelated implementation.

Provisioning MVP release gate: form-based profiles, static/derived BMC credentials, BIOS baselines, NetBox audit/repair, cabling/XLSX, two roles and real Ubuntu/Rocky deployment are integrated. FreeIPA/PostgreSQL follow in their tracked work package if they are not needed for the first rollout.

## 13. Phase 10 — FreeIPA, PostgreSQL and operations

Steps:

1. Implement the auth-provider interface using verified LDAPS/StartTLS and escaped LDAP searches. Authenticate without persisting user passwords.
2. Map immutable directory identities and configured groups to the existing two roles. Implement deliberate local-account linking, session invalidation and disabled/group-change behavior. Qualify MFA/nested/trusted-domain expectations against the actual deployment.
3. Preserve each user's separate NetBox credential and enforce visibility across results/events/exports. Do not replace it with a global service token for convenience.
4. Implement PostgreSQL repositories/migrations and run the same conformance suite. Explicitly test job claims, reservations and time semantics; keep a single executor until multiprocess recovery is qualified.
5. Add database migration tooling, consistent backups, artifact/key restore and recovery with execution disabled.
6. Add metrics, retention, quotas and runbooks for credential rotation, rate limits, broken media sessions, stale planned cables, uncertain actions and failed installs.
7. Load test the documented target sizes, measure requests per audit/host, tune budgets and record the measured limits.

Done when: FreeIPA users have the correct identity/role and own NetBox key; SQLite→PostgreSQL migration preserves state; a restored instance cannot accidentally replay destructive jobs; actual capacity and vendor limitations are documented.

## 14. Extension work packages

These use the established contracts; they are not hidden prerequisites of the provisioning MVP.

| Extension | Implementation boundary | Acceptance gate |
|---|---|---|
| QCOW2 deployment | Qualified image ingest/flattening, deploy ISO agent, raw disk writer, per-host first boot | Verify complete raw contents/zero regions, correct disk identity, bootability, unique host state and final readiness |
| Hardware RAID mutation | Controller-specific plan/apply/task/reinspect adapter | Explicit destructive plan, task recovery, new virtual-disk identities, fresh OS target approval |
| BIOS mutation | Attribute-registry validation, pending conflict detection, staged settings and approved reboot | Verify active settings after reboot; do not overwrite unrelated pending changes |
| Switch observation | Scoped SSH/NETCONF/SNMP LLDP driver | Correct peer normalization/freshness without changing switch configuration |
| Discovery ISO | Ephemeral authenticated inventory agent | Reads disks only; boot/reboot separately approved; stable identity and coverage verified |
| IPMI | Narrow inventory/power/boot fallback | Capability-specific behavior; no assumption of standard virtual media |
| PXE/iPXE | Explicit alternate boot transport | Uses the same deployment spec/workflow; never enables DHCP or network services implicitly |
| Remote site worker | Authenticated job dispatch, scoped credentials/artifacts, coordinated budgets | Restart/partition/revocation behavior; no duplicated uncertain destructive effects |
| Windows | Separate OS installer/verification backend | Dedicated media, unattended config, drivers and licensing/boot tests; no claim of support now |

## 15. End-to-end acceptance scenario

Prepare a controlled fixture/lab environment with host1 and host2 selected, host3 unselected, one stale serial, one missing physical interface, missing bond/VLAN/IP assignments, a wrong-VRF IP, one missing cable, a BIOS mismatch and a pending BIOS change. Include extra hosts in the allocation file and a competing port reservation.

1. Log in as named full user A with A's NetBox key. Select only host1/host2.
2. Create connection profiles through forms: one static credential and one secret-prefix + BMC-last-octet + secret-suffix recipe. Preview derivation without revealing secrets.
3. Inspect, restart Forge and view persisted evidence without unnecessarily repeating hardware requests.
4. Capture BIOS baseline from a known-good reference host, choose relevant settings and compatible variants, publish and audit peers. A different unqualified model must not pass by default; a pending desired value is not active compliance.
5. Import allocation data and preview only selected-host entries. Reject wrong VRF/conflict and preserve unrelated entries without creating extra devices.
6. Generate an audit plan. Wrong serial blocks installation and cannot be fixed by overwriting the expected identity automatically.
7. Approve a subset of NetBox repairs. Change one touched object externally; apply rejects the stale action and does not overwrite the new value.
8. Regenerate/approve and apply repairs. Inject 429 and a lost write response. Verify deferred retries, remote reconciliation and no duplicate objects.
9. Propose a redundant cable pair; do not double-reserve a switch port. Create planned records, export XLSX and record physical work independently.
10. Build and execute approved Ubuntu/Rocky installations on designated compatible lab targets. Verify exact target disks, final network/storage, current deployment identity and media cleanup.
11. Interrupt the controller after a remote command and restart. Verify it reconciles before any replay; uncertain destructive state becomes actionable attention.
12. Log in as readonly user B with B's NetBox key and narrower visibility. B can see/export only authorized results and cannot call mutation endpoints or expose A's credentials.
13. When Phase 10 is implemented, repeat identity/role tests via FreeIPA and persistence/recovery tests on PostgreSQL.

Do not mark the application complete until claimed capabilities pass their gates. Clearly list any hardware-dependent steps not run.

## 16. Prompt for the implementation agent

> Implement Forge in this repository using `docs/architecture.md`, `docs/profile-design.md` and `docs/implementation-plan.md`. Read all three first and preserve the user's requirements, particularly form-based profiles (no YAML/Kubernetes manifest editor), static and prefix/value/suffix derived BMC credentials, and BIOS baselines captured from compatible reference hosts. Use the real Mineral package at `/Users/danil/Development/mineral`. Work through the phases as usable vertical slices, starting with foundation, identity/jobs and per-user NetBox inventory. Maintain `docs/implementation-status.md` and continue through the selected milestone without replacing required behavior with mocks or claiming unrun hardware qualification. Use simulated adapters for development and keep live external mutation behind concrete approved plans. When a real NetBox version, OS image, vendor firmware or lab access is unavailable, implement and test the independent contracts, record the precise missing qualification evidence, and continue other work. Include relevant tests, actual results and remaining limitations in each handoff.

Suggested first implementation milestone: Phases 0–7, yielding a complete audit/BIOS-baseline/NetBox-repair/cabling application with XLSX. Then implement the Ubuntu/Rocky provisioning MVP (Phases 8–9) and identity/database operations (Phase 10). This is sequencing, not removal of the remaining requirements.
