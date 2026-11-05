<script lang="ts">
  import { onMount } from 'svelte';
  import { Panel, Button, Field, Input } from '@mineral-ui/design';
  import { api } from './api';

  type Secret = { id: string; label: string; kind: string; generation: number };
  type Connection = {
    driver: string; priority: number; address_source: string; address_field: string; username: string; port: number;
    password_mode: string; static_secret_id: string; prefix_secret_id: string; suffix_secret_id: string;
    padding_width: number; serial_last: number; serial_upper: boolean;
  };
  type Profile = { id: string; environment_id: string; name: string; row_version: number; published_revision: number; draft?: Connection; published?: Connection };
  type Preview = { mode: string; device_value: string; prefix_present: boolean; suffix_present: boolean };
  let { role }: { role: 'full' | 'readonly' } = $props();
  const defaults = (): Connection => ({ driver: 'redfish.generic', priority: 100, address_source: 'explicit', address_field: 'bmc_address', username: '', port: 443, password_mode: 'ipv4_octet', static_secret_id: '', prefix_secret_id: '', suffix_secret_id: '', padding_width: 0, serial_last: 4, serial_upper: false });
  const json = (body: object): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  let items = $state<Profile[]>([]);
  let secrets = $state<Secret[]>([]);
  let selectedID = $state('');
  let name = $state('');
  let rowVersion = $state(0);
  let draft = $state<Connection>(defaults());
  let secretLabel = $state('');
  let secretValue = $state('');
  let rotatingSecret = $state('');
  let error = $state('');
  let busy = $state(false);
  let previewIP = $state('');
  let previewSerial = $state('');
  let preview = $state<Preview | null>(null);

  async function reload() { items = await api<Profile[]>('/api/v1/profiles'); }
  async function loadSecrets() {
    secrets = [];
    if (role === 'full') secrets = await api<Secret[]>('/api/v1/shared-secrets');
  }
  async function chooseProfile(id: string) {
    selectedID = id; preview = null; error = '';
    if (!id) { name = ''; rowVersion = 0; draft = defaults(); return; }
    const p = items.find((item) => item.id === id); if (!p) return;
    name = p.name; rowVersion = p.row_version; draft = { ...(p.draft || p.published || defaults()) };
    try { await loadSecrets(); } catch (e) { error = e instanceof Error ? e.message : 'Could not load secrets'; }
  }
  async function addSecret() {
    error = ''; busy = true;
    try {
      if (rotatingSecret) await api(`/api/v1/shared-secrets/${encodeURIComponent(rotatingSecret)}`, { ...json({ value: secretValue }), method: 'PUT' });
      else await api('/api/v1/shared-secrets', json({ label: secretLabel, kind: 'bmc_credential', value: secretValue }));
      secretLabel = ''; secretValue = ''; rotatingSecret = ''; await loadSecrets();
    } catch (e) { error = e instanceof Error ? e.message : 'Could not add secret'; }
    finally { busy = false; }
  }
  async function save() {
    error = ''; busy = true; preview = null;
    try {
      const result = selectedID
        ? await api<Profile>(`/api/v1/profiles/${encodeURIComponent(selectedID)}/draft`, { ...json({ row_version: rowVersion, draft }), method: 'PUT' })
        : await api<Profile>('/api/v1/profiles', json({ name, draft }));
      selectedID = result.id; rowVersion = result.row_version; await reload();
    } catch (e) { error = e instanceof Error ? e.message : 'Could not save profile'; }
    finally { busy = false; }
  }
  async function publish() {
    error = ''; busy = true;
    try { await api(`/api/v1/profiles/${encodeURIComponent(selectedID)}/publish`, json({ row_version: rowVersion })); await reload(); const p = items.find((item) => item.id === selectedID); if (p) rowVersion = p.row_version; }
    catch (e) { error = e instanceof Error ? e.message : 'Profile validation failed'; }
    finally { busy = false; }
  }
  async function previewRecipe() {
    error = ''; busy = true;
    try { preview = await api<Preview>(`/api/v1/profiles/${encodeURIComponent(selectedID)}/preview`, json({ bmc_ip: previewIP, declared_serial: previewSerial })); }
    catch (e) { error = e instanceof Error ? e.message : 'Could not preview recipe'; }
    finally { busy = false; }
  }
  function changeMode() { draft.static_secret_id = ''; draft.prefix_secret_id = ''; draft.suffix_secret_id = ''; preview = null; }
  onMount(() => { void Promise.all([reload(), loadSecrets()]).catch((e) => { error = e instanceof Error ? e.message : 'Could not load profiles'; }); });
</script>

<Panel title="Connection profiles">
  <p>Configure Redfish connection settings with a stored password or a derived password recipe.</p>
  <p class="compact">Drafts and revisions are available. Inspection currently requires an explicit BMC address; automatic profile selection is still being implemented.</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if role === 'full'}
      <label for="profile-pick">Profile</label><select id="profile-pick" value={selectedID} onchange={(event) => chooseProfile(event.currentTarget.value)}><option value="">New connection profile</option>{#each items as item (item.id)}<option value={item.id}>{item.name}{items.filter((other) => other.name === item.name).length > 1 ? ` · ${item.id.slice(0, 8)}` : ''} · revision {item.published_revision || 'draft'}</option>{/each}</select>
      <form class="section-form" onsubmit={(event) => { event.preventDefault(); void addSecret(); }}>
        <p>Add or rotate a shared BMC secret for use as a password, prefix or suffix. Its value is not displayed after saving.</p>
        <label for="environment-secret-action">Secret action</label><select id="environment-secret-action" bind:value={rotatingSecret}><option value="">Add secret</option>{#each secrets as secret (secret.id)}<option value={secret.id}>Rotate {secret.label}</option>{/each}</select>
        {#if !rotatingSecret}<Field label="Secret label"><Input aria-label="Shared secret label" bind:value={secretLabel} required /></Field>{/if}
        <Field label="Secret value"><Input aria-label="Shared secret value" type="password" bind:value={secretValue} required /></Field>
        <Button type="submit" disabled={busy}>{rotatingSecret ? 'Rotate shared secret' : 'Add shared secret'}</Button>
      </form>
      <form class="section-form" onsubmit={(event) => { event.preventDefault(); void save(); }}>
        <Field label="Profile name"><Input aria-label="Connection profile name" bind:value={name} disabled={Boolean(selectedID)} required /></Field>
        <Field label="Username"><Input aria-label="BMC username" bind:value={draft.username} required /></Field>
        <Field label="Redfish HTTPS port"><Input aria-label="Redfish HTTPS port" type="number" min="1" max="65535" bind:value={draft.port} required /></Field>
        <Field label="Priority"><Input aria-label="Profile priority" type="number" bind:value={draft.priority} /></Field>
        <label for="address-source">BMC address source</label><select id="address-source" bind:value={draft.address_source}><option value="netbox_custom_field">NetBox custom field</option><option value="explicit">Explicit per-server binding</option></select>
        {#if draft.address_source === 'netbox_custom_field'}<Field label="NetBox field name"><Input aria-label="NetBox field name" bind:value={draft.address_field} required /></Field>{/if}
        <label for="password-mode">Password mode</label><select id="password-mode" bind:value={draft.password_mode} onchange={changeMode}><option value="static">Static password</option><option value="ipv4_octet">BMC IPv4 last octet</option><option value="serial_tail">End of NetBox serial</option></select>
        {#if draft.password_mode === 'static'}
          <label for="static-secret">Password secret</label><select id="static-secret" bind:value={draft.static_secret_id} required><option value="">Choose secret</option>{#each secrets as secret (secret.id)}<option value={secret.id}>{secret.label} · v{secret.generation}</option>{/each}</select>
        {:else}
          <label for="prefix-secret">Optional prefix</label><select id="prefix-secret" bind:value={draft.prefix_secret_id}><option value="">None</option>{#each secrets as secret (secret.id)}<option value={secret.id}>{secret.label} · v{secret.generation}</option>{/each}</select>
          {#if draft.password_mode === 'ipv4_octet'}<label for="padding">Octet formatting</label><select id="padding" bind:value={draft.padding_width}><option value={0}>Unpadded</option><option value={3}>Zero-padded to 3 digits</option></select>{:else}<Field label="Characters from end"><Input aria-label="Serial characters from end" type="number" min="1" max="128" bind:value={draft.serial_last} required /></Field><label class="checkbox-line"><input type="checkbox" bind:checked={draft.serial_upper} /> Uppercase serial fragment</label>{/if}
          <label for="suffix-secret">Optional suffix</label><select id="suffix-secret" bind:value={draft.suffix_secret_id}><option value="">None</option>{#each secrets as secret (secret.id)}<option value={secret.id}>{secret.label} · v{secret.generation}</option>{/each}</select>
        {/if}
        <div class="row-actions"><Button type="submit" disabled={busy}>Save draft</Button>{#if selectedID}<Button variant="accent" disabled={busy} onclick={publish}>Publish saved draft</Button>{/if}</div>
      </form>
      {#if selectedID}<form class="section-form" onsubmit={(event) => { event.preventDefault(); void previewRecipe(); }}>
        <p>Preview the saved draft. Secret segments remain masked.</p>
        {#if draft.password_mode === 'ipv4_octet'}<Field label="Resolved BMC IPv4"><Input aria-label="Preview BMC IPv4" bind:value={previewIP} placeholder="10.20.30.47" required /></Field>{:else if draft.password_mode === 'serial_tail'}<Field label="Declared NetBox serial"><Input aria-label="Preview NetBox serial" bind:value={previewSerial} required /></Field>{/if}
        <Button type="submit" disabled={busy}>Preview saved recipe</Button>
        {#if preview}<p>{#if preview.mode === 'static'}Stored password{:else}{preview.prefix_present ? '•••• + ' : ''}{preview.device_value}{preview.suffix_present ? ' + ••••' : ''}{/if}</p>{/if}
      </form>{/if}
  {:else}
    {#if items.length === 0}<p>No published profiles are available.</p>{:else}<div class="account-list">{#each items as item (item.id)}<div class="account-row"><span>{item.name}</span><small>Revision {item.published_revision}</small></div>{/each}</div>{/if}
  {/if}
</Panel>
