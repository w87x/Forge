<script lang="ts">
  import { onMount } from 'svelte';
  import { Panel, Button, Field, Input } from '@mineral-ui/design';
  import { api } from './api';

  type RecordData = { job_id: string; device_id: number; identity_status: string; observed: { bios_registry_coverage: string; bios_attribute_types: Record<string, string> | null; bios_attributes: Record<string, unknown> | null } };
  type Variant = { manufacturer: string; model: string; firmware: string; registry: string; attributes: Record<string, unknown>; reference_job_id: string };
  type Profile = { id: string; environment_id: string; name: string; row_version: number; published_revision: number; draft?: Variant[]; published?: Variant[] };
  type Finding = { attribute: string; status: string; expected: unknown; active: unknown; pending: unknown; pending_status: string };
  type Comparison = { status: string; reason?: string; findings: Finding[] };
  let { record, role } = $props<{record: RecordData | null; role: string}>();
  let profiles = $state<Profile[]>([]);
  let selectedProfile = $state('');
  let name = $state('');
  let chosen = $state<string[]>([]);
  let previousJob = $state('');
  let result = $state<Comparison | null>(null);
  let error = $state('');
  let busy = $state(false);
  let active = $derived(profiles.find((p) => p.id === selectedProfile));
  let candidates = $derived(Object.keys(record?.observed.bios_attribute_types || {}).filter((key) => record?.observed.bios_attributes && key in record.observed.bios_attributes).sort());
  const json = (body: object): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

  $effect(() => { if ((record?.job_id || '') !== previousJob) { previousJob = record?.job_id || ''; chosen = []; result = null; } });
  async function refresh() {
    try { profiles = await api<Profile[]>('/api/v1/bios-profiles'); }
    catch (e) { error = e instanceof Error ? e.message : 'Could not load BIOS profiles'; }
  }
  onMount(() => { void refresh(); });
  function toggle(key: string, checked: boolean) { chosen = checked ? [...chosen, key] : chosen.filter((item) => item !== key); }
  async function capture(existing: boolean) {
    if (!record || (existing && !active)) return;
    busy = true; error = '';
    try {
      const body = { job_id: record.job_id, attributes: chosen };
      const p = existing && active
        ? await api<Profile>(`/api/v1/bios-profiles/${encodeURIComponent(active.id)}/variants`, json({ ...body, row_version: active.row_version }))
        : await api<Profile>('/api/v1/bios-profiles', json({ ...body, name }));
      selectedProfile = p.id; name = ''; chosen = []; result = null; await refresh();
    } catch (e) { error = e instanceof Error ? e.message : 'Could not capture BIOS profile'; }
    finally { busy = false; }
  }
  async function publish() {
    if (!active) return;
    busy = true; error = '';
    try { await api(`/api/v1/bios-profiles/${encodeURIComponent(active.id)}/publish`, json({ row_version: active.row_version })); result = null; await refresh(); }
    catch (e) { error = e instanceof Error ? e.message : 'Could not publish BIOS profile'; }
    finally { busy = false; }
  }
  async function removeVariant(index: number) {
    if (!active) return;
    busy = true; error = '';
    try { await api(`/api/v1/bios-profiles/${encodeURIComponent(active.id)}/variants`, { ...json({ row_version: active.row_version, index }), method: 'DELETE' }); result = null; await refresh(); }
    catch (e) { error = e instanceof Error ? e.message : 'Could not remove variant'; }
    finally { busy = false; }
  }
  async function compare() {
    if (!active || !record) return;
    busy = true; error = '';
    try { result = await api<Comparison>(`/api/v1/bios-profiles/${encodeURIComponent(active.id)}/compare`, json({ revision: active.published_revision, job_id: record.job_id })); }
    catch (e) { error = e instanceof Error ? e.message : 'Could not compare BIOS profile'; }
    finally { busy = false; }
  }
</script>

<Panel title="BIOS profiles">
  <p>Capture selected settings from a recent, identity-matched inspection. Each variant applies to its exact vendor, model, firmware and BIOS registry.</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <label for="bios-profile">Profile</label>
  <select id="bios-profile" bind:value={selectedProfile} onchange={() => { result = null; }}>
    <option value="">Choose a profile</option>
    {#each profiles as profile (profile.id)}<option value={profile.id}>{profile.name}{profiles.filter((other) => other.name === profile.name).length > 1 ? ` · ${profile.id.slice(0, 8)}` : ''} · {profile.published_revision ? `revision ${profile.published_revision}` : 'draft'}</option>{/each}
  </select>
  <Button size="sm" variant="ghost" disabled={busy} onclick={refresh}>Refresh profiles</Button>
  {#if active}
    <p>Draft version {active.row_version} · published revision {active.published_revision || 'none'}</p>
    {#if active.draft}<details><summary>Draft variants ({active.draft.length})</summary>{#each active.draft as variant, index}<div><strong>{variant.manufacturer} {variant.model} · {variant.firmware}</strong><p>Registry {variant.registry} · reference job {variant.reference_job_id}</p>{#each Object.entries(variant.attributes) as [key,value]}<div class="account-row"><span>{key}</span><span>{String(value)}</span></div>{/each}{#if role === 'full'}<Button size="sm" variant="ghost" disabled={busy} onclick={() => removeVariant(index)}>Remove from draft</Button>{/if}</div>{/each}</details>{/if}
    {#if active.published}<details><summary>Published variants ({active.published.length})</summary>{#each active.published as variant}<div><strong>{variant.manufacturer} {variant.model} · {variant.firmware}</strong><p>Registry {variant.registry} · reference job {variant.reference_job_id}</p>{#each Object.entries(variant.attributes) as [key,value]}<div class="account-row"><span>{key}</span><span>{String(value)}</span></div>{/each}</div>{/each}</details>{/if}
    {#if role === 'full'}<Button size="sm" variant="accent" disabled={busy} onclick={publish}>Publish draft</Button>{/if}
    {#if record && active.published_revision}<Button size="sm" variant="ghost" disabled={busy} onclick={compare}>Compare current inspection</Button>{/if}
  {/if}
  {#if result}
    <p>Comparison: <strong>{result.status}</strong>{result.reason ? ` · ${result.reason}` : ''}</p>
    {#each result.findings as finding (finding.attribute)}<div class="account-row"><span>{finding.attribute} · {finding.status}</span><span>expected {String(finding.expected)} / active {String(finding.active)} / pending {finding.pending_status}{finding.pending_status !== 'unknown' ? ` (${String(finding.pending)})` : ''}</span></div>{/each}
  {/if}
  {#if role === 'full' && record}
    <div class="section-form">
      <strong>Capture from device #{record.device_id}</strong>
      {#if record.identity_status !== 'match'}<p>The NetBox serial must match the inspected server before capture.</p>
      {:else if record.observed.bios_registry_coverage !== 'available'}<p>A supported BIOS registry is required to classify settings.</p>
      {:else if !candidates.length}<p>No classified settings are available from this registry yet.</p>
      {:else}
        <p>Select the settings to copy. Unclassified settings are excluded.</p>
        {#each candidates as key (key)}<label><input type="checkbox" checked={chosen.includes(key)} onchange={(event) => toggle(key, event.currentTarget.checked)} /> {key} · {String(record.observed.bios_attributes?.[key])}</label>{/each}
        <Field label="New profile name"><Input aria-label="BIOS profile name" bind:value={name} /></Field>
        <Button size="sm" variant="accent" disabled={busy || !name.trim() || !chosen.length} onclick={() => capture(false)}>Create draft</Button>
        {#if active}<Button size="sm" variant="ghost" disabled={busy || !chosen.length} onclick={() => capture(true)}>Add or replace matching variant</Button>{/if}
      {/if}
    </div>
  {/if}
</Panel>
