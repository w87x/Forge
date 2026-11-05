# Forge

Architecture and implementation handoff for an operator-controlled bare-metal onboarding system.

Status: implementation has started. See the [implementation ledger](docs/implementation-status.md) for completed work and limitations.

- [Architecture](docs/architecture.md): responsibilities, data model, workflows, drivers, auth, deployment and acceptance criteria.
- [Profile editor design](docs/profile-design.md): form-based profile workflows, validation and a worked network allocation example.
- [Implementation plan](docs/implementation-plan.md): ordered work packages, tests and a ready-to-use implementation prompt.
- [Small-agent execution guide](docs/small-agent-plan.md): 100 bounded implementation tasks, explicit dependencies, checks, progress tracking and resumable session prompts.

Confirmed requirements: Go backend; Svelte frontend using Mineral; SQLite first and PostgreSQL later; NetBox inventory and per-user API keys; hardware inspection and approved remediation; cabling planning; Ubuntu/Rocky installation without PXE by default; Gigabyte/Lenovo/Yadro servers with Redfish; XLSX exports; bootstrap token and FreeIPA authentication; full and readonly roles.

Profile authoring is form-based from the MVP, not YAML/Kubernetes manifests. Connection profiles support static passwords and derived passwords with optional secret prefix/suffix around the last BMC IPv4 octet or other configured device data. BIOS compliance profiles can be captured from a reference host and have vendor/model/firmware-compatible variants.

The installed NetBox version, exact server models/firmware and Linux release versions remain to be discovered. Do not infer NetBox API compatibility from a guessed release year or major version.

Local paths:

- Forge: `/Users/danil/Develpoment/forge` (the spelling of `Develpoment` is intentional in this existing path).
- Mineral: `/Users/danil/Development/mineral`, package `@mineral-ui/design`, Svelte 5.

Recommended implementation order: inventory and inspection → deterministic audit → approved NetBox repair → cabling → Ubuntu ISO deployment → Rocky ISO deployment → FreeIPA and operational qualification. QCOW2 deployment and hardware RAID changes follow as separately qualified capabilities.

## Local development

Install Go and Node, then run `make build`. Generate two independent secrets and store them securely:

```sh
openssl rand -base64 32  # FORGE_ENCRYPTION_KEY; keep this stable across restarts
openssl rand -base64 32  # FORGE_BOOTSTRAP_TOKEN; needed for initial setup only
```

Set those environment variables to the generated values, then run `FORGE_DEV_INSECURE_HTTP=true ./bin/forge` and open `http://127.0.0.1:8080`. The insecure development cookie setting is limited to a loopback listener. For deployment behind HTTPS, omit that setting and provide appropriate TLS termination. `FORGE_DATABASE_PATH` and `FORGE_LISTEN_ADDR` can override the default database and loopback address.

The bootstrap screen creates the first named full-access user and displays a login token once. Save it securely. A preliminary NetBox device view, connection-profile editor, read-only Redfish inspection and BIOS baseline workflow are available. Full hardware/network compliance, cabling and provisioning are still planned.

Forge uses one shared list of users, connections and profiles. Full users manage shared profiles and BMC credentials; readonly users can view published profiles. Each user supplies their own NetBox key, and stored inspection evidence remains scoped to its operator. Legacy internal scope IDs are retained during upgrades so existing encrypted credentials remain usable.

Hardware compliance profiles can check serial/model identity, CPU and memory thresholds, and a minimum number of drives with distinct observed serials. Full users can save a hardware-only audit against an inspection; its result is tied to the published profile revision and remains visible only to its owner with current NetBox visibility. Missing, stale or incomplete evidence is reported as unknown. Physical NIC mapping, complete interface documentation and RAID inspection are not yet available and cannot pass those checks.

To allow a read-only NetBox connection check, set `FORGE_NETBOX_ALLOWED_HOSTS` to a comma-separated list of the exact NetBox hostnames or host:port pairs. HTTPS is required by default. `FORGE_ALLOW_NETBOX_HTTP=true` explicitly permits HTTP for environments that need it. The check currently reports API reachability and the reported version; it does not establish the NetBox identity or enable writes.

For the initial read-only Redfish inspection, set `FORGE_BMC_ALLOWED_CIDRS` to the management networks allowed for inspection, for example `192.0.2.0/24`. `FORGE_BMC_CA_FILE` can add a PEM CA to the system trust store; certificates must still match the BMC IP address. Publish an explicit-address connection profile, freeze a device selection, then start an inspection. This initial adapter uses HTTP Basic authentication and requires a BMC exposing exactly one Redfish system. It records system identity, available active/pending BIOS attributes, and bounded samples of reported Ethernet interfaces and drives. Hardware coverage is partial and Ethernet interfaces are not assumed to represent physical ports. Real vendor hardware has not yet been qualified.

After viewing a successful inspection, use the BIOS profiles panel to select classified settings, create a draft, and publish a revision. Reference and comparison inspections must be less than 24 hours old and their serials must match NetBox. Variants require exact vendor, model, firmware and registry content matches. Registry discovery currently requires a locally hosted English registry and includes only a small conservative allowlist of settings; unsupported or missing evidence is reported as unknown. Pending values are shown separately from active compliance.

The network profile form saves physical interfaces, bonds, VLANs, bridges and network rows, and validates the saved topology before publishing an immutable revision. VRFs and VLANs can be loaded with the operator's own NetBox key; references are tied to that connection and are not yet revalidated at publication. A Kayobe-style YAML file can be uploaded for a selected-device allocation preview and saved after validation. Saved imports retain only selected-device bindings and addresses; reopening them requires a fresh selection of the same devices. A read-only device check compares up to four visible interface and IP-address pages each, MTUs, reported bond/bridge membership and selected VLAN tags with that import. Incomplete evidence and global address conflicts remain unknown, and no NetBox write is performed.

Combined audits compose a saved hardware check, a saved network check for the same device and an optional published BIOS profile. They preserve the resulting findings and source references. Network evidence older than five minutes and hardware evidence older than 24 hours are marked stale; reopening results requires current visibility of both sources.

For local fixture-only development, set `FORGE_SIMULATION=true` before starting the server. Simulation uses `data/simulation/forge.db` by default, displays a visible simulation label, and exposes a harmless sample job and fake device list. The database records its mode and cannot later be opened in normal mode. This mode does not contact NetBox or BMCs.
