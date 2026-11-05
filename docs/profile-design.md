# Profile editor design

Profiles are form-based application objects. **Do not implement Kubernetes-style manifests or a YAML/JSON profile text editor, even as an MVP shortcut.** The API stores typed JSON; that representation is not the operator workflow. YAML remains supported for Kayobe-style address allocation imports only.

**Updated workspace decision:** All profiles share one list. Environment fields, selectors and membership management mentioned in older sections are superseded. Server applicability is still expressed through typed NetBox attributes and profile criteria.

## 1. Shared behavior

The profile list shows name, kind, published revision, draft state, matching-server count, last author and validation status. Actions: create, duplicate, edit draft, preview on servers, publish, archive. Readonly users can inspect published profiles and their resolved effects but cannot edit or publish.

Use a common shell with sections for identity, applicability, kind-specific settings, validation and impact. A profile has a human name, description, environment and optional applicability criteria. Criteria use field/operator/value rows with typed selectors: site, location, rack, manufacturer, device type, role, tags and approved custom fields. Show “matches N of selected M servers” and actual examples. Provide an explicit priority control; show and block equal-priority ambiguities.

Draft saving does not affect running jobs or existing assignments. Publishing creates an immutable revision. Editing a published profile creates a new draft. Assignments/bundles pin revisions; adopting a newer revision is an explicit operation with an impact preview, not a silent global rollout. A profile can be valid but inapplicable to particular hardware; display that separately.

Validation runs both client-side for immediate field errors and authoritatively on the server. A cross-profile “preview on selected servers” resolves references, NetBox IDs, bindings and adapter capabilities without changing external systems. Place each error beside its field and in a linked error summary. Do not hide missing capability behind a green “saved” indicator.

All selectors display useful names plus disambiguating context, while the API pins stable IDs. For example, a VLAN selector shows name, VLAN number, scope and NetBox ID. A VRF name alone may not be unique. Secret controls show a credential label and owner/scope, never a stored value.

Suggested UI sequence:

```text
Profiles → New profile → Choose type → Fill sections
         → Preview on selected servers → Resolve validation
         → Publish revision → Assign through onboarding bundle
```

A side panel shows a human-readable resolved summary and expected changes. A generated JSON download may exist for diagnostics/backup later, but users must never need to edit it to configure a supported feature. Script source editing is allowed where the thing being authored is actually a script; that does not justify a profile-manifest editor.

## 2. Connection profile

| Section | Controls |
|---|---|
| Applicability | Environment, vendor/model/role selectors, priority |
| Driver | Generic Redfish or a qualified vendor adapter; capability summary |
| BMC address | Source picker: NetBox custom field, explicit management IP/interface binding, per-server override |
| Target | Port, optional TLS name, unique discovered Redfish system or explicit system binding |
| Credentials | Username; password mode: **Static** or **Derived** |
| Trust | CA selector/certificate pin; explicit environment exception if necessary |
| Limits | Request timeout, inspection deadline, cache TTL and concurrency |
| Preview/test | Selected server, resolved endpoint, masked credential recipe; explicit “Test connection” action |

“Test connection” is available to full users and performs bounded authentication/read-only discovery, not power or configuration changes. It is logged and rate-limited per BMC. Publishing a profile must not automatically test it against every matching server.

### Static password

Choose an existing encrypted credential or enter a password through a secure password field. On save the backend stores it encrypted and returns only its reference/label. Static credentials can be shared by an environment profile or overridden per server through an explicitly scoped binding.

### Derived password: primary preset

Provide this simple form first:

```text
Password mode         Derived
Prefix                [optional secret value / existing secret]
Device value          [Last octet of BMC IPv4 ▾]
Number format         [Unpadded decimal ▾]  or  [Zero-padded width: 3]
Suffix                [optional secret value / existing secret]

Preview server        host1
Resolved BMC IP       10.20.30.47
Extracted value       47
Password structure    •••• + 47 + ••••
```

Support prefix only, suffix only, prefix plus suffix and static passwords as first-class MVP behavior. Either secret segment may be absent; validate the final result against configured length constraints without displaying it. If an operator intentionally selects only the device value, present the exact recipe for review rather than silently adding a prefix/suffix.

Examples of the derivation, where `P` and `S` denote secret references:

| Mode | BMC IPv4 | Format | Derived result, symbolic only |
|---|---|---|---|
| Static | Any supported target | — | Stored secret |
| Prefix + value | 10.20.30.47 | Decimal | P + `47` |
| Value + suffix | 10.20.30.47 | Decimal | `47` + S |
| Prefix + value + suffix | 10.20.30.47 | Width 3 | P + `047` + S |
| Prefix + value + suffix | 10.20.30.7 | Decimal | P + `7` + S |

The connection address and derivation input must be the same resolved canonical management IPv4. Never use the operating-system primary IP by accident. Parse the IP; do not split a URL on periods. Reject malformed inputs and ambiguous hostname resolution. An explicit bound IPv4 can be used with a separate TLS server name. IPv6 has no IPv4 last octet; require a different recipe or static password for IPv6-only targets.

Derive just before connecting and retain the result only in memory for that operation/session. Keep it out of logs, persisted jobs, raw request dumps, observations, exports and error messages. Prefix/suffix values are secrets even if the operator enters them inline. Store only the recipe, secret references and source-field fingerprints in plans. Secret rotation or address changes force fresh resolution; never replay an obsolete calculated credential blindly.

### Advanced recipe

An optional segment builder supports ordered rows such as:

```text
[Secret: BMC prefix]
+[NetBox serial → last 6 characters → uppercase]
+[Secret: BMC suffix]
```

Allowed sources/transforms are explicit enums with typed controls: BMC IPv4 octet, declared NetBox serial, substring/from-end, trim, upper/lowercase, decimal zero-padding. Specify string indexing semantics (Unicode code points, zero-based start/end for a range) and fail on too-short serials; do not silently produce a partial value. Preview source transformations without exposing secret segments or final passwords. Prevent arbitrary templating, shell execution, environment-variable access and recursive recipes.

NetBox serial can be used on the very first login because it is already declared inventory. Redfish-observed serial cannot be the prerequisite for that login. After authentication, compare observed identity with NetBox before any destructive action. A credential recipe does not set/reset the remote password. Failed authentication does not try guessed formatting variants or another profile's password, which could lock the BMC account.

## 3. Hardware compliance and BIOS baseline editors

Use rule rows with `Category`, `Field`, `Comparison`, `Expected value`, `Severity`, `Blocks installation`, and evidence availability. Category-specific controls avoid a free-form expression language.

Examples:

| Category | Rule | Expected control |
|---|---|---|
| NetBox | Required fields | Multi-select: serial, model, role, rack, location, etc. |
| Identity | Observed serial matches NetBox | Normalization picker; mismatch blocks installation |
| CPU | Socket/core counts | Integer minimum/exact/range |
| RAM | Total capacity | Number + GiB unit |
| NICs | All physical ports represented | Scope/exclusion selectors and stable-identity requirement |
| Disks | Count/capacity/media | Typed constraints and identity requirements |
| RAID | Expected observed controller layout | Controller/volume rule table; audit-only initially |
| BIOS | Selected active attribute equals expected | Vendor attribute picker + typed allowed-value control |

BIOS inspection collects current attributes, attribute-registry metadata and pending values where exposed. Attribute keys and enum values are vendor/model/firmware-specific; populate selectors from a representative inspected server and show applicability. Unknown/unsupported attributes remain unknown, not compliant. Separate current and pending columns; a pending desired value does not mean the active setting already complies.

Preserve native attribute names and optionally map a small set of normalized concepts (e.g. virtualization) only through a qualified adapter. Do not invent a universal setting name for all three vendors. An attribute registry may provide allowed values, read-only flags, dependencies and help text; the UI uses those when present and clearly marks incomplete metadata. Redfish defines BIOS attributes and their registry, and commonly uses a settings resource for changes requiring a reset. [DMTF BIOS schema](https://redfish.dmtf.org/schemas/v1/Bios.v1_2_3.json)

BIOS **audit** belongs in the inspection release. BIOS **mutation**, if implemented, is a separate capability and approved plan: validate writable values/dependencies → show active/pending diff → stage → apply at approved reset → re-read active values. Preserve unrelated pending changes and stop on conflicts; never issue “reset BIOS to defaults” as a generic repair. This extension is not a firmware flashing feature.

### Capture a BIOS profile from a reference server

This is a first-class BIOS profile type linked from the hardware/onboarding views, not a manual key/value transcription task.

1. Open a server's BIOS tab and choose **Create baseline from this host**. Alternatively start a new BIOS profile and pick the reference server.
2. Choose a complete recent observation or explicitly refresh through the read-only inspector. Show vendor, model/SKU, BIOS/BMC versions, registry ID/hash and capture time. Require known compatibility evidence before publishing an enforceable baseline.
3. Display a searchable table of active attributes with description, type, current value, allowed values, read-only flag, pending value and inclusion checkbox. Capture only active values by default. Exclude secret/password fields, machine-specific identifiers, device-instance-specific boot paths and transient/counter values; explain each exclusion. Unknown sensitivity is excluded until classified, and sensitive values never enter the profile payload.
4. Operator chooses the relevant settings. Read-only attributes may be included as audit expectations, clearly distinguished from remediable ones. Allow intentional expected-value edits with valid typed controls; show that the expected value differs from the captured source. Add severity and install-blocking behavior by rule or group.
5. Confirm **Applies to**: manufacturer, model/SKU, registry identity/content and compatible firmware. Default narrowly to the captured family; widening firmware/model support requires a deliberate compatibility preview and evidence. CPU generation/controller constraints can further restrict a variant where a setting depends on installed hardware.
6. Preview against selected hosts: matched variant, matching settings, mismatches, pending changes, unavailable attributes, unsupported model and insufficient evidence. No matching variant is not a compliance pass. If the onboarding bundle requires BIOS coverage, a coverage gap blocks installation.
7. Publish a revision, retaining reference-host UUID, source observation/hash, capture time, native registry and operator changes. Updating the source host later does not alter published expectations. **Recapture** creates a new draft with a diff.

One named baseline can contain variants, each with its own reference host and compatible family. For example, “Compute BIOS standard” can have a Lenovo model-A variant and a Gigabyte model-B variant; a Yadro family is added using its own capture/qualified mapping. A clone copies intent into a draft, but does not certify that another vendor's keys or enum values are equivalent. Exact duplicate or overlapping variant matches are validation errors; narrow their applicability so exactly one variant matches each supported target.

Comparison operates on typed native attribute identifiers. Registry-hash changes force compatibility review rather than silently accepting a reused registry name. Attribute absence is unknown/unsupported, not “disabled.” A target whose active value differs but pending value matches shows **noncompliant, change pending** until reboot and reinspection. Merely capturing/publishing a baseline never stages settings or reboots a server.

## 4. Network editor

Provide a table/tree and a generated topology preview. A drag-only canvas is not required. Controls: “Add physical port,” “Add bond,” “Add VLAN,” “Add bridge,” and later “Add Linux VRF.” Physical ports reference per-host identity bindings instead of assuming every server has the same kernel names.

Each editor has appropriate fields: bond members/mode/monitoring; VLAN parent/number/NetBox VLAN; bridge members; MTU; OS and NetBox naming conventions. Detect cycles, duplicate names, invalid membership, unsupported nesting and MTU inconsistencies. Display netbox/interface bindings beside actual observed MAC/PCI labels.

Network rows attach addressing intent to a chosen graph node:

| Network | Interface | Allocation group | Prefix | NetBox VRF | OS route |
|---|---|---|---|---|---|
| Control | bond0.110 | ctl_ips | 192.0.2.0/24 | Control / ID 10 | Default via 192.0.2.1 |
| Tunnel | bond0.120 | tun_ips | 198.51.100.0/24 | Tunnel / ID 20 | Connected route only |

Prefix/VRF/VLAN pickers fetch authorized NetBox objects. Set primary address, DNS, routes and allocation policy through fields. Linux VRFs have their own explicit controls and routing-table IDs; they are not created simply because NetBox uses a VRF.

Per-server binding drawer example: `uplink A → permanent MAC → PCI port → NetBox eno1 → OS eno1`. Propose a match from evidence, show confidence/ambiguity, and require resolution for conflicting mappings. The common graph may use logical binding names `uplink A/B`, avoiding duplicate profiles for every NIC naming variation.

### Allocation import: YAML is data here

Upload the existing file:

```yaml
ctl_ips:
  host1: 192.0.2.11
  host2: 192.0.2.12
  unselected-host: 192.0.2.99
tun_ips:
  host1: 198.51.100.11
  host2: 198.51.100.12
  unselected-host: 198.51.100.99
```

If only host1 (NetBox device 101) is selected, the preview contains only `192.0.2.11/24 → bond0.110 / VRF 10` and `198.51.100.11/24 → bond0.120 / VRF 20`. Show “2 unselected hosts ignored,” with the unit explicit. Do not select/create/import those extra hosts.

Map the file's groups to network rows with dropdowns. Display missing selected-host entries, conflicting addresses, wrong prefixes and ambiguous host aliases as row-level errors. Operator aliases are explicit. A malformed YAML document fails parsing; unrelated hosts' scalar value errors need not block selected valid hosts. Store the source hash and mapping revision for reproducibility.

IPv4/IPv6 and multiple addresses can be supported by a defined extension; do not silently change what a scalar map means. No Jinja/Ansible execution is performed.

## 5. Storage editor

Use mode cards: existing/inspect-only, software RAID/LVM, or supported hardware RAID. Show capability restrictions before allowing selection.

Disk selectors use discovered identities and typed policy fields: serial/WWN, controller/slot, count, capacity/media, explicit exclusions. Resolve the selector on each selected server and display concrete disks. A policy that matches zero/too many disks cannot be applied. Never default to the first disk or wipe all attached storage.

The layout builder starts with tested templates (single disk, two-disk mirror with LVM) and exposes supported sizes, filesystem choices, mount points, swap and data preservation. Preview disk → GPT partitions → RAID → volume group → logical volumes. Unsupported custom combinations remain disabled with an explanation; do not offer a general free-form config field as an escape hatch.

For a mirrored UEFI OS, show an ESP on each target, bootloader targets and the qualified ESP synchronization mechanism separately from mdraid root. Display a renderer capability matrix for Ubuntu/Rocky and require a degraded-boot qualification before claiming resilience. Hardware RAID has controller-specific fields and a separate destructive action before OS targeting is re-resolved.

## 6. Cabling editor

Pick permitted switches by filter or explicit list. Set same-rack preference, neighboring-rack order, fallback scope, port tags/roles, speed/media, cable type/length policy and redundancy groups. Rack adjacency is an ordered table/map, not inferred from rack names.

Show each server uplink and required switch group (e.g. A/B fabrics). Specify distinct-switch requirements and any approved MLAG/stack association when choosing LACP. The example dual-uplink profile can use active-backup when that fits the network; do not select a bond mode without showing the topology implications.

Preview candidate ports with explanations and rejected alternatives. Reservations have expiry and visible ownership. Keep “create planned NetBox cable,” “physical work confirmed,” and “observed peer matches” as separate states and actions. XLSX exports are available from the preview and work list.

## 7. Installation editor

Wizard sections: OS/release/image → transport → network/storage references → users/keys → packages/files/hooks → readiness → resolved preview.

Use artifact pickers with distribution, architecture, digest and qualification status. Ubuntu and Rocky have separate renderers; unsupported releases/layouts cannot silently reuse another renderer. A later Windows backend can have its own controls without exposing Windows in the MVP as a working option.

Users are table rows with name, groups, SSH key sets and login policy. Files are upload/library rows with destination, owner and mode. Hooks are uploaded/selected scripts with phase, interpreter, timeout, expected exit codes and retry semantics; source preview is available. Review content hashes and warn when a new script revision changes a deployment plan. Do not run uploaded scripts on the controller during preview/build.

Readiness controls select SSH credential/profile, host-key enrollment policy, required identity/OS/network/storage/service checks and deadline. Preview the final host-specific settings and exact destructive disk targets before producing an installation plan. Merely publishing a profile never starts installation.

## 8. Onboarding bundle, change review and UI components

A bundle is a form containing profile pickers, pinned revision selectors and per-server override bindings. Its preview compares NetBox, observed state and resolved desired state. Display missing required profiles and unsupported driver/renderer combinations together.

The resulting repair plan has dependency-aware checkboxes and structured before/after fields. For example: create bond0 → create bond0.110 → allocate/assign control IP → set primary IPv4. Required prerequisites become visibly selected; unrelated cabling/install work stays separate. A stale plan displays the changed source fields and requires regenerated approval.

Use Mineral's `Panel`, `Field`, `Input`, `Select`, `MultiSelect`, `Checkbox`, `Switch`, `NumberInput`, `Tabs`, `Badge`, `Diff` and `Button`. Create Forge-specific components such as `ProfileSelector`, `CredentialRecipe`, `RuleTable`, `InterfaceTree`, `DiskLayoutPreview`, `ObjectPicker` and `ImpactPreview` using Mineral tokens. Build accessible semantic tables; add dialog focus trapping/restoration. Form usability is part of the MVP acceptance criteria, not a later polish phase.
