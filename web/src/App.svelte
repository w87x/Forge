<script lang="ts">
  import { onMount } from 'svelte';
  import { Panel, Button, Field, Input, Badge } from '@mineral-ui/design';
  import { api } from './api';
  import ProfileEditor from './ProfileEditor.svelte';
  import BIOSProfiles from './BIOSProfiles.svelte';
  import NetworkProfiles from './NetworkProfiles.svelte';
  import CablingProfiles from './CablingProfiles.svelte';
  import HardwareProfiles from './HardwareProfiles.svelte';
  import CombinedAudits from './CombinedAudits.svelte';

  let status = $state<'checking' | 'connected' | 'offline'>('checking');
  let message = $state('Checking the service connection.');
  let filter = $state('');
  type User = { id: string; username: string; role: 'full' | 'readonly'; disabled: boolean };
  let user = $state<User | null>(null);
  let authView = $state<'loading' | 'bootstrap' | 'token' | 'login' | 'app'>('loading');
  let bootstrapSecret = $state('');
  let username = $state('');
  let loginToken = $state('');
  let issuedToken = $state('');
  let authError = $state('');
  let busy = $state(false);
  let newUsername = $state('');
  let newRole = $state<'full' | 'readonly'>('readonly');
  let createdToken = $state('');
  let users = $state<User[]>([]);
  type Secret = { id: string; label: string; kind: string; generation: number };
  let secrets = $state<Secret[]>([]);
  let selectedSecret = $state('');
  let secretLabel = $state('');
  let secretKind = $state('other');
  let secretValue = $state('');
  type SimDevice = { name: string; bmc_address: string; vendor: string; selected: boolean };
  type Job = { id: string; kind: string; status: string; attempts: number };
  type JobEvent = { sequence: number; type: string; message: string; at: string };
  let simulation = $state(false);
  let devices = $state<SimDevice[]>([]);
  let jobs = $state<Job[]>([]);
  let selectedJob = $state('');
  let jobEvents = $state<JobEvent[]>([]);
  let streamStatus = $state('');
  let stream: EventSource | null = null;
  type NetBoxInstance = { id: string; environment_id: string; name: string; base_url: string };
  type NetBoxCredential = { instance_id: string; generation: number; updated_at: string };
  let netboxInstances = $state<NetBoxInstance[]>([]);
  let netboxCredentials = $state<NetBoxCredential[]>([]);
  let instanceName = $state('');
  let instanceURL = $state('');
  let selectedInstance = $state('');
  let netboxToken = $state('');
  type NetBoxReport = { reachable: boolean; api_version: string; authentication: string; writes_enabled: boolean; checked_at: string };
  let netboxReport = $state<NetBoxReport | null>(null);
  let reportInstance = $state('');
  type InventoryDevice = { id: number; forge_id: string; name: string; serial: string; site: string; rack?: string; role: string; model: string; manufacturer: string; status: string };
  type InventorySnapshot = { id: string; instance_id: string; filter: { offset: number }; devices: InventoryDevice[]; count: number; has_more: boolean; fetched_at: string; expires_at: string };
  type InventorySelection = { id: string; snapshot_id: string; device_ids: number[] };
  let snapshot = $state<InventorySnapshot | null>(null);
  let selection = $state<InventorySelection | null>(null);
  type NetBoxInterfacePage = {results: {id:number; name:string; type:string; enabled:boolean|null; mtu:number|null; mac:string; mode:string; parent_id:number|null; parent_known:boolean; lag_id:number|null; lag_known:boolean; bridge_id:number|null; bridge_known:boolean; untagged_vlan_id:number|null; untagged_vlan_known:boolean; tagged_vlan_ids:number[]; tagged_vlans_known:boolean; cable_id:number|null; cable_state:string}[];count:number;offset:number;has_more:boolean};
  let interfaceDevice = $state('');
  let interfacePage = $state<NetBoxInterfacePage | null>(null);
  type NetBoxAddressPage = {results:{id:number;address:string;status:string;vrf_id:number|null;vrf_name:string;interface_id:number;interface_name:string}[];count:number;offset:number;has_more:boolean};
  let addressPage = $state<NetBoxAddressPage | null>(null);
  let selectedDevices = $state<number[]>([]);
  let siteFilter = $state('');
  let roleFilter = $state('');
  let deviceStatus = $state('');
  type InspectionProfile = { id: string; environment_id: string; name: string; published_revision: number; published?: { address_source: string } };
  type InspectionRecord = { job_id: string; device_id: number; bmc_ip: string; declared_serial: string; identity_status: string; collected_at: string; observed: { manufacturer: string; model: string; serial: string; bios_version: string; bios_coverage: string; bios_registry_coverage: string; bios_registry: string; bios_attribute_types: Record<string, string> | null; bios_attributes: Record<string, unknown> | null; pending_coverage: string; pending_attributes: Record<string, unknown> | null; nic_coverage: string; disk_coverage: string; volume_coverage?:string; volumes?:{path:string;id:string;name:string;raid_type:string;capacity_bytes:number|null;health:string;state:string;drive_paths:string[]}[] | null; interfaces: {path: string; id: string; name: string; mac: string; permanent_mac: string; speed_mbps: number | null; link_status: string; kind: string; health?:string; state?:string}[] | null; drives: {path: string; id: string; manufacturer: string; model: string; serial: string; capacity_bytes: number | null; protocol: string; media_type: string; revision?:string; health?:string; state?:string}[] | null } };
  let inspectionProfiles = $state<InspectionProfile[]>([]);
  let inspectionProfile = $state('');
  let inspectionDevice = $state('');
  let bmcAddress = $state('');
  let inspectionRecord = $state<InspectionRecord | null>(null);

  const json = (body: object): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  async function loadSession() {
    try {
      simulation = (await api<{simulation: boolean}>('/api/v1/info')).simulation;
      const setup = await api<{setup_needed: boolean}>('/api/v1/auth/bootstrap-status');
      if (setup.setup_needed) { authView = 'bootstrap'; return; }
      try { user = await api<User>('/api/v1/me'); authView = 'app'; await loadAccountData(user); }
      catch { authView = 'login'; }
    } catch (error) { authError = error instanceof Error ? error.message : 'Unable to reach Forge'; authView = 'login'; }
  }
  async function bootstrap() {
    authError = ''; busy = true;
    try {
      const result = await api<{user: User; token: string}>('/api/v1/auth/bootstrap', json({ token: bootstrapSecret, username }));
      issuedToken = result.token; bootstrapSecret = ''; authView = 'token';
    } catch (error) { authError = error instanceof Error ? error.message : 'Setup failed'; }
    finally { busy = false; }
  }
  async function login() {
    authError = ''; busy = true;
    try {
      const result = await api<{user: User}>('/api/v1/auth/login', json({ token: loginToken }));
      user = result.user; loginToken = ''; issuedToken = ''; authView = 'app'; await loadAccountData(user);
    } catch (error) { authError = error instanceof Error ? error.message : 'Login failed'; }
    finally { busy = false; }
  }
  async function logout() {
    try { await api('/api/v1/auth/logout', { method: 'POST' }); stream?.close(); stream = null; user = null; createdToken = ''; secrets = []; users = []; jobs = []; devices = []; netboxInstances = []; netboxCredentials = []; inspectionProfiles = []; inspectionRecord = null; jobEvents = []; snapshot = null; selection = null; selectedDevices = []; secretValue = ''; netboxToken = ''; authView = 'login'; }
    catch (error) { authError = error instanceof Error ? error.message : 'Logout failed'; }
  }
  async function createUser() {
    authError = ''; busy = true;
    try {
      const result = await api<{user: User; token: string}>('/api/v1/users', json({ username: newUsername, role: newRole }));
      createdToken = result.token; newUsername = ''; if (user) await loadAccountData(user);
    } catch (error) { authError = error instanceof Error ? error.message : 'Could not create user'; }
    finally { busy = false; }
  }
  async function loadAccountData(actor: User) {
    try {
      secrets = await api<Secret[]>('/api/v1/me/secrets');
      users = actor.role === 'full' ? await api<User[]>('/api/v1/users') : [];
      netboxInstances = await api<NetBoxInstance[]>('/api/v1/netbox/instances');
      netboxCredentials = await api<NetBoxCredential[]>('/api/v1/netbox/credentials');
      if (simulation) devices = await api<SimDevice[]>('/api/v1/simulation/devices');
      jobs = await api<Job[]>('/api/v1/jobs');
      inspectionProfiles = await api<InspectionProfile[]>('/api/v1/profiles');
    } catch (error) { authError = error instanceof Error ? error.message : 'Could not load account data'; }
  }
  async function refreshInspectionProfiles() {
    try { inspectionProfiles = await api<InspectionProfile[]>('/api/v1/profiles'); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not load profiles'; }
  }
  async function startInspection() {
    if (!selection) return;
    const profile = inspectionProfiles.find((item) => item.id === inspectionProfile);
    if (!profile) return;
    authError = ''; busy = true; inspectionRecord = null;
    try {
      const request = json({ selection_id: selection.id, device_id: Number(inspectionDevice), profile_id: profile.id, revision: profile.published_revision, bmc_ip: bmcAddress });
      const job = await api<Job>('/api/v1/inspections', { ...request, headers: { 'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID() } });
      await refreshJobs(); watchJob(job.id);
    } catch (error) { authError = error instanceof Error ? error.message : 'Could not start inspection'; }
    finally { busy = false; }
  }
  async function viewInspection(job: Job) {
    await openInspection(job.id);
  }
  async function openInspection(id: string) {
    authError = ''; busy = true; inspectionRecord = null;
    try { inspectionRecord = await api<InspectionRecord>(`/api/v1/inspections/${encodeURIComponent(id)}`); document.getElementById('inspection-evidence')?.scrollIntoView({behavior:'smooth'}); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not load inspection'; }
    finally { busy = false; }
  }
  async function createInstance() {
    authError = ''; busy = true;
    try { const instance = await api<NetBoxInstance>('/api/v1/netbox/instances', json({ name: instanceName, base_url: instanceURL })); instanceName = ''; instanceURL = ''; selectedInstance = instance.id; if (user) await loadAccountData(user); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not add NetBox instance'; }
    finally { busy = false; }
  }
  async function saveNetBoxToken() {
    authError = ''; busy = true;
    try { await api(`/api/v1/netbox/instances/${encodeURIComponent(selectedInstance)}/credential`, { ...json({ token: netboxToken }), method: 'PUT' }); netboxToken = ''; netboxReport = null; snapshot = null; selection = null; selectedDevices = []; if (user) await loadAccountData(user); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not save NetBox key'; }
    finally { busy = false; }
  }
  async function deleteNetBoxToken() {
    if (!confirm('Delete your NetBox key for this instance?')) return;
    authError = ''; busy = true;
    try { await api(`/api/v1/netbox/instances/${encodeURIComponent(selectedInstance)}/credential`, { method: 'DELETE' }); netboxReport = null; snapshot = null; selection = null; selectedDevices = []; if (user) await loadAccountData(user); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not delete NetBox key'; }
    finally { busy = false; }
  }
  async function fetchInventory(offset = 0) {
    authError = ''; busy = true;
    try {
      snapshot = await api<InventorySnapshot>(`/api/v1/netbox/instances/${encodeURIComponent(selectedInstance)}/inventory`, json({ query: filter, site_id: Number(siteFilter) || 0, role_id: Number(roleFilter) || 0, status: deviceStatus, offset }));
      selectedDevices = []; selection = null;
    } catch (error) { authError = error instanceof Error ? error.message : 'Could not refresh inventory'; }
    finally { busy = false; }
  }
  function toggleDevice(id: number, checked: boolean) {
    selectedDevices = checked ? [...selectedDevices, id] : selectedDevices.filter((item) => item !== id);
    selection = null;
  }
  async function freezeSelection() {
    if (!snapshot) return;
    authError = ''; busy = true;
    try { selection = await api<InventorySelection>('/api/v1/inventory/selections', json({ snapshot_id: snapshot.id, device_ids: selectedDevices })); interfaceDevice=''; interfacePage=null; addressPage=null; }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not save selection'; }
    finally { busy = false; }
  }
  async function loadInterfaces(offset = 0) {
    if (!selection || !interfaceDevice) return;
    const selectionID=selection.id, device=interfaceDevice;
    authError=''; busy=true;
    try { const page=await api<NetBoxInterfacePage>(`/api/v1/inventory/selections/${encodeURIComponent(selectionID)}/interfaces`,json({device_id:Number(device),offset})); if(selection?.id===selectionID && interfaceDevice===device) interfacePage=page; }
    catch(error){authError=error instanceof Error?error.message:'Could not load interfaces';}
    finally{busy=false;}
  }
  async function loadAddresses(offset = 0) {
    if (!selection || !interfaceDevice) return;
    const selectionID=selection.id, device=interfaceDevice; authError=''; busy=true;
    try { const page=await api<NetBoxAddressPage>(`/api/v1/inventory/selections/${encodeURIComponent(selectionID)}/addresses`,json({device_id:Number(device),offset})); if(selection?.id===selectionID && interfaceDevice===device) addressPage=page; }
    catch(error){authError=error instanceof Error?error.message:'Could not load IP addresses';}
    finally{busy=false;}
  }
  async function testNetBox() {
    authError = ''; busy = true;
    try { netboxReport = await api<NetBoxReport>(`/api/v1/netbox/instances/${encodeURIComponent(selectedInstance)}/test`, { method: 'POST' }); reportInstance = selectedInstance; }
    catch (error) { netboxReport = null; authError = error instanceof Error ? error.message : 'NetBox connection failed'; }
    finally { busy = false; }
  }
  async function refreshJobs() {
    try { jobs = await api<Job[]>('/api/v1/jobs'); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not refresh jobs'; }
  }
  async function runSimulation() {
    authError = ''; busy = true;
    try {
      const job = await api<Job>('/api/v1/simulation/jobs', { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } });
      await refreshJobs(); watchJob(job.id);
    } catch (error) { authError = error instanceof Error ? error.message : 'Could not start simulation'; }
    finally { busy = false; }
  }
  async function cancelJob(job: Job) {
    authError = ''; busy = true;
    try { await api(`/api/v1/jobs/${encodeURIComponent(job.id)}/cancel`, { method: 'POST' }); await refreshJobs(); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not cancel job'; }
    finally { busy = false; }
  }
  function watchJob(id: string) {
    stream?.close(); selectedJob = id; jobEvents = []; streamStatus = 'Connecting';
    const source = new EventSource(`/api/v1/jobs/${encodeURIComponent(id)}/events`); stream = source;
    source.onopen = () => { streamStatus = 'Live'; };
    source.onerror = () => { streamStatus = 'Reconnecting'; };
    source.addEventListener('job', (raw) => {
      const event = JSON.parse((raw as MessageEvent).data) as JobEvent;
      if (!jobEvents.some((existing) => existing.sequence === event.sequence)) jobEvents = [...jobEvents, event];
      void refreshJobs();
      if (['succeeded', 'failed', 'cancelled', 'needs_attention'].includes(event.type)) { source.close(); streamStatus = 'Complete'; }
    });
  }
  async function revokeUser(target: User) {
    if (!confirm(`Revoke all login tokens and sessions for ${target.username}?`)) return;
    authError = ''; busy = true;
    try {
      await api(`/api/v1/users/${encodeURIComponent(target.id)}/revoke-tokens`, { method: 'POST' });
      if (target.id === user?.id) { user = null; authView = 'login'; }
      else if (user) await loadAccountData(user);
    } catch (error) { authError = error instanceof Error ? error.message : 'Could not revoke tokens'; }
    finally { busy = false; }
  }
  async function issueToken(target: User) {
    authError = ''; busy = true;
    try { const result = await api<{token: string}>(`/api/v1/users/${encodeURIComponent(target.id)}/tokens`, { method: 'POST' }); createdToken = result.token; }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not issue token'; }
    finally { busy = false; }
  }
  async function saveSecret() {
    authError = ''; busy = true;
    try {
      if (selectedSecret) await api(`/api/v1/me/secrets/${encodeURIComponent(selectedSecret)}`, { ...json({ value: secretValue }), method: 'PUT' });
      else await api('/api/v1/me/secrets', json({ label: secretLabel, kind: secretKind, value: secretValue }));
      secretValue = ''; secretLabel = ''; selectedSecret = ''; if (user) await loadAccountData(user);
    } catch (error) { authError = error instanceof Error ? error.message : 'Could not save secret'; }
    finally { busy = false; }
  }
  async function deleteSecret(item: Secret) {
    if (!confirm(`Delete the stored secret “${item.label}”?`)) return;
    authError = ''; busy = true;
    try { await api(`/api/v1/me/secrets/${encodeURIComponent(item.id)}`, { method: 'DELETE' }); if (user) await loadAccountData(user); }
    catch (error) { authError = error instanceof Error ? error.message : 'Could not delete secret'; }
    finally { busy = false; }
  }

  async function checkConnection() {
    status = 'checking';
    try {
      await api<{ status: string }>('/healthz');
      status = 'connected';
      message = 'The Forge service is responding.';
    } catch (error) {
      status = 'offline';
      message = error instanceof Error ? error.message : 'Could not reach the Forge service.';
    }
  }
  onMount(() => { void checkConnection(); void loadSession(); return () => stream?.close(); });
</script>

<svelte:head><title>Forge · Bare metal operations</title></svelte:head>

<div class="shell">
  <header class="masthead">
    <div><p class="eyebrow">Infrastructure operations</p><h1>FORGE<span class="mark">_</span></h1></div>
    <div class="header-actions">{#if simulation}<Badge tone="attn">SIMULATION</Badge>{/if}<div class="header-status"><span class:online={status === 'connected'} class="status-dot"></span>{status === 'connected' ? 'SERVICE ONLINE' : status === 'offline' ? 'SERVICE OFFLINE' : 'CONNECTING'}</div>{#if user}<Button variant="ghost" onclick={logout}>Log out</Button>{/if}</div>
  </header>
  {#if authView !== 'app'}
    <main class="auth-layout">
      {#if authView === 'loading'}
        <p>Checking your session…</p>
      {:else if authView === 'bootstrap'}
        <Panel title="First-time setup" tone="accent">
          <p>Create the first full-access user using the server's bootstrap token.</p>
          <form onsubmit={(event) => { event.preventDefault(); void bootstrap(); }}>
            <Field label="Username"><Input aria-label="Username" bind:value={username} required /></Field>
            <Field label="Bootstrap token"><Input aria-label="Bootstrap token" type="password" bind:value={bootstrapSecret} required /></Field>
            {#if authError}<p class="error" role="alert">{authError}</p>{/if}
            <Button type="submit" variant="accent" loading={busy}>Create first user</Button>
          </form>
        </Panel>
      {:else if authView === 'token'}
        <Panel title="Save your login token" tone="attn">
          <p>This token is shown once. Save it somewhere secure before continuing.</p>
          <Field label="Login token"><Input aria-label="Issued login token" value={issuedToken} readonly /></Field>
          <div><Button variant="accent" onclick={() => { loginToken = issuedToken; authView = 'login'; }}>Continue to login</Button></div>
        </Panel>
      {:else}
        <Panel title="Sign in" tone="accent">
          <p>Use the login token issued to your named account.</p>
          <form onsubmit={(event) => { event.preventDefault(); void login(); }}>
            <Field label="Login token"><Input aria-label="Login token" type="password" bind:value={loginToken} required /></Field>
            {#if authError}<p class="error" role="alert">{authError}</p>{/if}
            <Button type="submit" variant="accent" loading={busy}>Sign in</Button>
          </form>
        </Panel>
      {/if}
    </main>
  {:else}
  <div class="app-layout">
    <aside aria-label="Application navigation">
      <div class="nav-label">WORKSPACE</div>
      <div class="nav-active" aria-current="page"><span>◈</span> Overview</div>
      <div class="nav-disabled">Inventory <small>EARLY</small></div>
      <div class="nav-disabled">Profiles <small>EARLY</small></div>
      <div class="nav-disabled">Jobs <small>EARLY</small></div>
    </aside>
    <main>
      <div class="page-head"><div><p class="eyebrow">WORKSPACE / OVERVIEW</p><h2>Operations overview</h2><p class="intro">Signed in as {user?.username} · {user?.role}</p></div><Badge>FOUNDATION</Badge></div>
      {#if authError}<p class="error" role="alert">{authError}</p>{/if}
      <div class="content-grid">
        <ProfileEditor role={user?.role || 'readonly'} />
        <HardwareProfiles role={user?.role || 'readonly'} record={inspectionRecord} />
        <NetworkProfiles role={user?.role || 'readonly'} {selection} {netboxInstances} selectedDevices={snapshot?.devices.filter((device) => selection?.device_ids.includes(device.id)) || []} />
        <CablingProfiles role={user?.role || 'readonly'} {netboxInstances} />
        {#if simulation}
          <Panel title="Simulation fixtures" tone="attn">
            <p>Example data only. Simulation does not inspect or change real infrastructure.</p>
            <div class="account-list">{#each devices as device (device.name)}<div class="account-row"><span>{device.name} <small>· {device.vendor} · {device.bmc_address}</small></span><small>{device.selected ? 'SELECTED' : 'UNSELECTED'}</small></div>{/each}</div>
            {#if user?.role === 'full'}<div><Button variant="attn" disabled={busy} onclick={runSimulation}>Run sample job</Button></div>{/if}
          </Panel>
        {/if}
        <Panel title="Jobs">
          {#if jobs.length === 0}<p>No jobs yet.</p>{:else}<div class="account-list">{#each jobs as job (job.id)}<div class="account-row"><span>{job.kind} <small>· {job.status}</small></span><div class="row-actions"><Button size="sm" variant="ghost" onclick={() => watchJob(job.id)}>View events</Button>{#if job.kind === 'redfish.inspect' && job.status === 'succeeded'}<Button size="sm" variant="ghost" disabled={busy} onclick={() => viewInspection(job)}>View inspection</Button>{/if}{#if user?.role === 'full' && ['queued', 'running', 'retry_wait', 'waiting_remote', 'awaiting_approval'].includes(job.status)}<Button size="sm" variant="ghost" disabled={busy} onclick={() => cancelJob(job)}>Cancel</Button>{/if}</div></div>{/each}</div>{/if}
          {#if selectedJob}<div class="timeline"><p>Job events · {streamStatus}</p>{#each jobEvents as event (event.sequence)}<div class="timeline-event"><small>#{event.sequence}</small><span>{event.message}</span></div>{/each}</div>{/if}
        </Panel>
        <div id="inspection-evidence"><Panel title="Redfish inspection">
          {#if user?.role !== 'full'}<p>Only full-access operators can start inspections.</p>{:else if simulation}<p>Real BMC connections are disabled in simulation.</p>{:else if !selection || !snapshot}<p>Fetch devices and freeze a selection before inspecting a server.</p>{:else}
            <p>Inspects the selected server with a published profile and an explicit, allowed BMC address. TLS verification is required.</p>
            <form onsubmit={(event) => { event.preventDefault(); void startInspection(); }}>
              <label for="inspection-device">Selected device</label><select id="inspection-device" bind:value={inspectionDevice} required><option value="">Choose device</option>{#each snapshot.devices.filter((device) => selection?.device_ids.includes(device.id)) as device (device.id)}<option value={String(device.id)}>{device.name || device.id} · {device.serial || 'serial unknown'}</option>{/each}</select>
              <label for="inspection-profile">Published connection profile</label><select id="inspection-profile" bind:value={inspectionProfile} required><option value="">Choose profile</option>{#each inspectionProfiles.filter((profile) => profile.published_revision > 0 && profile.published?.address_source === 'explicit') as profile (profile.id)}<option value={profile.id}>{profile.name}{inspectionProfiles.filter((other) => other.name === profile.name).length > 1 ? ` · ${profile.id.slice(0, 8)}` : ''} · revision {profile.published_revision}</option>{/each}</select>
              <Button size="sm" variant="ghost" disabled={busy} onclick={refreshInspectionProfiles}>Refresh profiles</Button>
              <Field label="BMC IP address"><Input aria-label="Inspection BMC IP address" bind:value={bmcAddress} placeholder="192.0.2.47" required /></Field>
              <Button type="submit" variant="accent" loading={busy}>Start read-only inspection</Button>
            </form>
          {/if}
          {#if inspectionRecord}
            <div class="section-form"><p>Device #{inspectionRecord.device_id} · {inspectionRecord.bmc_ip} · {new Date(inspectionRecord.collected_at).toLocaleString()}</p>
              <p>Serial: NetBox {inspectionRecord.declared_serial || 'unknown'} / observed {inspectionRecord.observed.serial || 'unknown'} · {inspectionRecord.identity_status}</p>
              <p>{inspectionRecord.observed.manufacturer} {inspectionRecord.observed.model} · BIOS {inspectionRecord.observed.bios_version || 'unknown'}</p>
              <p>BIOS: {inspectionRecord.observed.bios_coverage} · registry: {inspectionRecord.observed.bios_registry_coverage || 'unknown'}{inspectionRecord.observed.bios_registry ? ` (${inspectionRecord.observed.bios_registry})` : ''} · pending: {inspectionRecord.observed.pending_coverage} · NICs: {inspectionRecord.observed.nic_coverage} · disks: {inspectionRecord.observed.disk_coverage} · volumes: {inspectionRecord.observed.volume_coverage || 'unknown'}</p>
              {#if inspectionRecord.observed.bios_attributes}<details><summary>Active BIOS attributes</summary>{#each Object.entries(inspectionRecord.observed.bios_attributes) as [key, value] (key)}<div class="account-row"><span>{key}</span><span>{String(value)}</span></div>{/each}</details>{/if}
              {#if inspectionRecord.observed.pending_attributes}<details><summary>Pending BIOS attributes</summary>{#each Object.entries(inspectionRecord.observed.pending_attributes) as [key, value] (key)}<div class="account-row"><span>{key}</span><span>{String(value)}</span></div>{/each}</details>{/if}
              {#if inspectionRecord.observed.interfaces}<details><summary>Reported Ethernet interfaces ({inspectionRecord.observed.interfaces.length})</summary><p>These can be logical interfaces; physical-port identity is not established.</p>{#each inspectionRecord.observed.interfaces as iface (iface.path)}<div class="account-row"><span>{iface.name || iface.id || iface.path}</span><span>MAC {iface.mac || 'unknown'} · permanent {iface.permanent_mac || 'unknown'} · {iface.speed_mbps === null ? 'speed unknown' : `${iface.speed_mbps} Mbps`} · {iface.link_status || 'link unknown'} · health {iface.health || 'unknown'} · state {iface.state || 'unknown'}</span></div>{/each}</details>{/if}
              {#if inspectionRecord.observed.volumes}<details><summary>Reported logical volumes ({inspectionRecord.observed.volumes.length})</summary><p>Volume coverage is partial; this does not verify the intended RAID configuration.</p>{#each inspectionRecord.observed.volumes as volume (volume.path)}<div class="account-row"><span>{volume.name || volume.id || volume.path} · {volume.raid_type || 'RAID type unknown'}</span><span>{volume.capacity_bytes === null ? 'capacity unknown' : `${volume.capacity_bytes} bytes`} · health {volume.health || 'unknown'} · state {volume.state || 'unknown'} · {volume.drive_paths.length} reported drive links</span></div>{/each}</details>{/if}
              {#if inspectionRecord.observed.drives}<details><summary>Reported drives ({inspectionRecord.observed.drives.length})</summary>{#each inspectionRecord.observed.drives as drive (drive.path)}<div class="account-row"><span>{drive.manufacturer} {drive.model || drive.id || drive.path} · serial {drive.serial || 'unknown'}</span><span>{drive.capacity_bytes === null ? 'capacity unknown' : `${drive.capacity_bytes} bytes`} · {drive.protocol || 'protocol unknown'} · {drive.media_type || 'media unknown'} · firmware {drive.revision || 'unknown'} · health {drive.health || 'unknown'} · state {drive.state || 'unknown'}</span></div>{/each}</details>{/if}
            </div>
          {/if}
        </Panel>
        </div>
        <BIOSProfiles record={inspectionRecord} role={user?.role || 'readonly'} />
        <CombinedAudits role={user?.role || 'readonly'} {selection} {openInspection} />
        <Panel title="Service connection" tone="accent">
          <div class="service-line"><span class:online={status === 'connected'} class="status-dot large"></span><div><strong>{status === 'connected' ? 'Connected' : status === 'offline' ? 'Unavailable' : 'Connecting'}</strong><p>{message}</p></div></div>
          <div><Button variant="accent" onclick={checkConnection}>Check connection</Button></div>
        </Panel>
        <Panel title="Getting started">
          <p>Forge is being assembled in stages. Inspection and onboarding controls will appear here as they become available.</p>
          <div class="empty-rule"></div>
          <p>Configure a NetBox connection and your own API key to read devices.</p>
        </Panel>
        {#if user?.role === 'full'}
          <Panel title="NetBox connections">
              <form onsubmit={(event) => { event.preventDefault(); void createInstance(); }}>
                <Field label="NetBox name"><Input aria-label="NetBox name" bind:value={instanceName} required /></Field><Field label="NetBox URL"><Input aria-label="NetBox URL" bind:value={instanceURL} type="url" placeholder="https://netbox.example" required /></Field>
                <Button type="submit" loading={busy}>Add NetBox instance</Button>
              </form>
          </Panel>
          <Panel title="Create user">
            <form onsubmit={(event) => { event.preventDefault(); void createUser(); }}>
              <Field label="Username"><Input aria-label="New username" bind:value={newUsername} required /></Field>
              <label for="new-role">Role</label><select id="new-role" bind:value={newRole}><option value="readonly">Read only</option><option value="full">Full access</option></select>
              {#if authError}<p class="error" role="alert">{authError}</p>{/if}
              <Button type="submit" loading={busy} disabled={Boolean(createdToken)}>Create user</Button>
            </form>
            {#if createdToken}<div class="issued"><p>Save the new user's token. It will not be shown again.</p><Field label="New user token"><Input aria-label="New user token" value={createdToken} readonly /></Field><Button variant="ghost" onclick={() => { createdToken = ''; }}>Dismiss</Button></div>{/if}
            <div class="account-list">{#each users as account (account.id)}<div class="account-row"><span>{account.username} <small>· {account.role}</small></span><div class="row-actions"><Button size="sm" variant="ghost" disabled={busy || Boolean(createdToken)} onclick={() => issueToken(account)}>Issue token</Button><Button size="sm" variant="ghost" disabled={busy} onclick={() => revokeUser(account)}>Revoke tokens</Button></div></div>{/each}</div>
          </Panel>
        {/if}
        <Panel title="My NetBox key">
          {#if netboxInstances.length === 0}<p>No NetBox connection has been configured.</p>{:else}
            <p>Register your own API key for an instance. Keys are stored encrypted and cannot be viewed after saving.</p>
            <form onsubmit={(event) => { event.preventDefault(); void saveNetBoxToken(); }}>
              <label for="netbox-instance">Instance</label><select id="netbox-instance" bind:value={selectedInstance} onchange={() => { snapshot = null; selection = null; selectedDevices = []; }} required><option value="">Select instance</option>{#each netboxInstances as instance (instance.id)}<option value={instance.id}>{instance.name} · {instance.base_url}</option>{/each}</select>
              {#if selectedInstance}<p class="compact">{netboxCredentials.some((item) => item.instance_id === selectedInstance) ? 'Key registered' : 'No key registered'}</p>{/if}
              <Field label="NetBox API key"><Input aria-label="NetBox API key" type="password" bind:value={netboxToken} required /></Field>
              <div class="row-actions"><Button type="submit" loading={busy}>Save or rotate key</Button>{#if netboxCredentials.some((item) => item.instance_id === selectedInstance)}<Button variant="danger" disabled={busy} onclick={deleteNetBoxToken}>Delete key</Button>{/if}</div>
            </form>
            {#if netboxCredentials.some((item) => item.instance_id === selectedInstance)}<div class="section-form"><Button variant="accent" disabled={busy || simulation} onclick={testNetBox}>Test connection</Button>{#if simulation}<p class="compact">Real connections are disabled in simulation.</p>{/if}{#if netboxReport && reportInstance === selectedInstance}<p class="compact">API reachable · version {netboxReport.api_version}. Authentication is unverified; writes are disabled.</p>{/if}</div>{/if}
          {/if}
        </Panel>
        <Panel title="Device inventory">
          {#if !selectedInstance || !netboxCredentials.some((item) => item.instance_id === selectedInstance)}<p>Select a NetBox instance and register your key above.</p>{:else if simulation}<p>Real NetBox reads are disabled in simulation.</p>{:else}
            <form onsubmit={(event) => { event.preventDefault(); void fetchInventory(); }}>
              <Field label="Search"><Input aria-label="Search NetBox devices" bind:value={filter} placeholder="Name or text" /></Field>
              <div class="filter-row"><Field label="Site ID"><Input aria-label="Site ID" bind:value={siteFilter} type="number" min="0" /></Field><Field label="Role ID"><Input aria-label="Role ID" bind:value={roleFilter} type="number" min="0" /></Field><Field label="Status"><Input aria-label="Device status" bind:value={deviceStatus} placeholder="active" /></Field></div>
              <Button type="submit" variant="accent" loading={busy}>Fetch devices</Button>
            </form>
            {#if snapshot && snapshot.instance_id === selectedInstance}
              <p class="compact">{snapshot.count} matching devices · fetched {new Date(snapshot.fetched_at).toLocaleString()} · selection applies to this page (up to 50 devices).</p>
              <div class="table-wrap"><table><thead><tr><th scope="col">Select</th><th scope="col">Device</th><th scope="col">Site / rack / role</th><th scope="col">Model / serial</th></tr></thead><tbody>{#each snapshot.devices as device (device.id)}<tr><td><input type="checkbox" aria-label={`Select ${device.name || device.id}`} checked={selectedDevices.includes(device.id)} onchange={(event) => toggleDevice(device.id, event.currentTarget.checked)} /></td><td>{device.name || `Device ${device.id}`}<small> #{device.id}</small></td><td>{device.site || '—'} / {device.rack || '—'} / {device.role || '—'}</td><td>{device.manufacturer} {device.model}<small> {device.serial}</small></td></tr>{/each}</tbody></table></div>
              {#if snapshot.devices.length === 0}<p>No devices matched this page.</p>{/if}
              <div class="row-actions"><Button size="sm" disabled={busy || snapshot.filter.offset === 0} onclick={() => fetchInventory(Math.max(0, snapshot!.filter.offset - 50))}>Previous page</Button><Button size="sm" disabled={busy || !snapshot.has_more} onclick={() => fetchInventory(snapshot!.filter.offset + snapshot!.devices.length)}>Next page</Button><Button size="sm" variant="accent" disabled={busy || selectedDevices.length === 0} onclick={freezeSelection}>Freeze selection ({selectedDevices.length})</Button></div>
              {#if selection}<p class="compact">Saved selection {selection.id} with {selection.device_ids.length} devices.</p>
                <div class="section-form"><label for="interface-device">View NetBox interfaces and IP addresses</label><select id="interface-device" bind:value={interfaceDevice} onchange={() => { interfacePage=null; addressPage=null; }}><option value="">Choose selected device</option>{#each snapshot.devices.filter((device) => selection?.device_ids.includes(device.id)) as device (device.id)}<option value={String(device.id)}>{device.name || device.id}</option>{/each}</select><Button size="sm" variant="ghost" disabled={busy || !interfaceDevice} onclick={() => loadInterfaces()}>Fetch interfaces</Button><Button size="sm" variant="ghost" disabled={busy || !interfaceDevice} onclick={() => loadAddresses()}>Fetch IP addresses</Button>
                  {#if interfacePage}<p>{interfacePage.count} reported interfaces · page offset {interfacePage.offset}. Cable endpoints are not loaded yet.</p><div class="table-wrap"><table><thead><tr><th scope="col">Interface</th><th scope="col">Type / MAC</th><th scope="col">Relationships</th></tr></thead><tbody>{#each interfacePage.results as iface (iface.id)}<tr><td>{iface.name} <small>#{iface.id}</small></td><td>{iface.type || 'unknown'} <small>{iface.mac || 'MAC unknown'} · {iface.mtu === null ? 'MTU unknown' : `MTU ${iface.mtu}`}</small></td><td>LAG {iface.lag_known ? iface.lag_id ?? '—' : 'unknown'} · parent {iface.parent_known ? iface.parent_id ?? '—' : 'unknown'} · bridge {iface.bridge_known ? iface.bridge_id ?? '—' : 'unknown'}<small>VLAN {iface.untagged_vlan_known ? iface.untagged_vlan_id ?? 'none' : 'unknown'} / {iface.tagged_vlans_known ? iface.tagged_vlan_ids.join(', ') || 'none' : 'unknown'} · cable {iface.cable_state || 'unknown'}{iface.cable_id ? ` (#${iface.cable_id})` : ''}</small></td></tr>{/each}</tbody></table></div><div class="row-actions"><Button size="sm" disabled={busy || interfacePage.offset===0} onclick={() => loadInterfaces(Math.max(0,interfacePage!.offset-50))}>Previous interfaces</Button><Button size="sm" disabled={busy || !interfacePage.has_more} onclick={() => loadInterfaces(interfacePage!.offset+interfacePage!.results.length)}>Next interfaces</Button></div>{/if}
                  {#if addressPage}<p>{addressPage.count} reported IP addresses · page offset {addressPage.offset}.</p><div class="table-wrap"><table><thead><tr><th scope="col">Address</th><th scope="col">VRF</th><th scope="col">Interface</th></tr></thead><tbody>{#each addressPage.results as ip (ip.id)}<tr><td>{ip.address}<small>{ip.status || 'status unknown'}</small></td><td>{ip.vrf_id===null ? 'Global' : `${ip.vrf_name || 'VRF'} (#${ip.vrf_id})`}</td><td>{ip.interface_name || 'Unnamed'} <small>#{ip.interface_id}</small></td></tr>{/each}</tbody></table></div><div class="row-actions"><Button size="sm" disabled={busy || addressPage.offset===0} onclick={() => loadAddresses(Math.max(0,addressPage!.offset-50))}>Previous IPs</Button><Button size="sm" disabled={busy || !addressPage.has_more} onclick={() => loadAddresses(addressPage!.offset+addressPage!.results.length)}>Next IPs</Button></div>{/if}
                </div>
              {/if}
            {/if}
          {/if}
        </Panel>
        <Panel title="My secrets">
          <p>Store credentials for later integrations. Secret values cannot be viewed after saving.</p>
          <form onsubmit={(event) => { event.preventDefault(); void saveSecret(); }}>
            <label for="secret-select">Action</label><select id="secret-select" bind:value={selectedSecret}><option value="">Add a secret</option>{#each secrets as item (item.id)}<option value={item.id}>Rotate {item.label}</option>{/each}</select>
            {#if !selectedSecret}
              <Field label="Label"><Input aria-label="Secret label" bind:value={secretLabel} required /></Field>
              <label for="secret-kind">Type</label><select id="secret-kind" bind:value={secretKind}><option value="other">Other</option><option value="netbox_token">NetBox token</option><option value="bmc_password">BMC password</option></select>
            {/if}
            <Field label="Secret value"><Input aria-label="Secret value" type="password" bind:value={secretValue} required /></Field>
            <Button type="submit" loading={busy}>{selectedSecret ? 'Rotate secret' : 'Save secret'}</Button>
          </form>
          <div class="account-list">{#each secrets as item (item.id)}<div class="account-row"><span>{item.label} <small>· {item.kind} · v{item.generation}</small></span><Button size="sm" variant="ghost" disabled={busy} onclick={() => deleteSecret(item)}>Delete</Button></div>{/each}</div>
        </Panel>
      </div>
      <div class="footnote">NETBOX INVENTORY · HARDWARE INSPECTION · CONTROLLED PROVISIONING</div>
    </main>
  </div>
  {/if}
</div>
