<script lang="ts">
  import { onMount } from 'svelte';
  import { Panel, Button, Field, Input } from '@mineral-ui/design';
  import { api } from './api';
  import AuditFinding from './AuditFinding.svelte';
  type Hardware = {require_serial:boolean;require_model:boolean;manufacturer:string;model:string;min_cpu_sockets:number;min_memory_gib:number;min_drives:number;min_physical_nics:number;require_interfaces_documented:boolean;raid_expectation:string};
  type Profile = {id:string;name:string;row_version:number;published_revision:number;draft?:Hardware;published?:Hardware};
  type Result = {status:string;findings:{rule:string;status:string;message:string;blocks_install:boolean;severity?:string;source?:string;evidence_at?:string;expected?:unknown;actual?:unknown}[]};
  type Audit = {id:string;profile_id:string;revision:number;job_id:string;created_at:string;result?:Result};
  let {role, record} = $props<{role:string;record:{job_id:string;device_id:number}|null}>();
  const defaults = ():Hardware => ({require_serial:true,require_model:true,manufacturer:'',model:'',min_cpu_sockets:0,min_memory_gib:0,min_drives:0,min_physical_nics:0,require_interfaces_documented:false,raid_expectation:''});
  const json=(body:object):RequestInit=>({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  let profiles=$state<Profile[]>([]);let selected=$state('');let name=$state('');let draft=$state<Hardware>(defaults());let saved=$state('');let busy=$state(false);let error=$state('');let result=$state<Result|null>(null);let previousJob=$state('');
  let audits=$state<Audit[]>([]);let resultLabel=$state('');
  let active=$derived(profiles.find((p)=>p.id===selected));let editing=$derived(role==='full');let dirty=$derived(JSON.stringify(draft)!==saved);
  $effect(()=>{if((record?.job_id||'')!==previousJob){previousJob=record?.job_id||'';result=null;}});
  async function refresh(){try{profiles=await api<Profile[]>('/api/v1/hardware-profiles');}catch(e){error=e instanceof Error?e.message:'Could not load hardware profiles';}}
  async function loadAudits(){try{audits=await api<Audit[]>('/api/v1/hardware-audits');}catch(e){error=e instanceof Error?e.message:'Could not load hardware audits';}}
  onMount(()=>{void refresh();void loadAudits();});
  function choose(){let p=profiles.find((item)=>item.id===selected);name=p?.name||'';draft={...(p?.draft||p?.published||defaults())};saved=JSON.stringify(draft);result=null;}
  async function save(){busy=true;error='';try{let p=selected&&active?await api<Profile>(`/api/v1/hardware-profiles/${encodeURIComponent(selected)}/draft`,{...json({row_version:active.row_version,draft:$state.snapshot(draft)}),method:'PUT'}):await api<Profile>('/api/v1/hardware-profiles',json({name,draft:$state.snapshot(draft)}));await refresh();selected=p.id;choose();}catch(e){error=e instanceof Error?e.message:'Could not save hardware profile';}finally{busy=false;}}
  async function publish(){if(!active)return;busy=true;error='';try{await api(`/api/v1/hardware-profiles/${encodeURIComponent(active.id)}/publish`,json({row_version:active.row_version}));await refresh();choose();}catch(e){error=e instanceof Error?e.message:'Could not publish hardware profile';}finally{busy=false;}}
  async function preview(save=false){if(!active||!record)return;const jobID=record.job_id,id=active.id,revision=active.published_revision;busy=true;error='';result=null;try{const path=save?'audits':'preview';const value=await api<Result|Audit>(`/api/v1/hardware-profiles/${encodeURIComponent(id)}/${path}`,json({revision,job_id:jobID}));if(record?.job_id===jobID&&active?.id===id&&active.published_revision===revision){result=save?(value as Audit).result||null:value as Result;resultLabel=save?'Saved hardware audit':'Hardware preview';}if(save)await loadAudits();}catch(e){error=e instanceof Error?e.message:'Could not evaluate hardware';}finally{busy=false;}}
  async function viewAudit(id:string){busy=true;error='';try{const item=await api<Audit>(`/api/v1/hardware-audits/${encodeURIComponent(id)}`);result=item.result||null;resultLabel=`Saved audit · revision ${item.revision} · ${new Date(item.created_at).toLocaleString()}`;}catch(e){error=e instanceof Error?e.message:'Could not load hardware audit';}finally{busy=false;}}
</script>

<Panel title="Hardware compliance profiles">
  <p>Define required hardware evidence. Missing or incomplete evidence stays unknown; installation is not yet implemented.</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <label for="hardware-profile">Profile</label><select id="hardware-profile" bind:value={selected} onchange={choose}><option value="">{editing?'New hardware profile':'Choose profile'}</option>{#each profiles as p (p.id)}<option value={p.id}>{p.name} · {p.published_revision?`revision ${p.published_revision}`:'draft'}</option>{/each}</select>
  {#if editing || active}
    {#if active}<p>Draft version {active.row_version} · published revision {active.published_revision||'none'}</p>{/if}
    <fieldset disabled={!editing}>
      {#if editing}<Field label="Profile name"><Input aria-label="Hardware profile name" bind:value={name} disabled={Boolean(selected)} /></Field>{/if}
      <label><input type="checkbox" bind:checked={draft.require_serial} /> Require matching NetBox serial</label>
      <label><input type="checkbox" bind:checked={draft.require_model} /> Require matching NetBox model</label>
      <Field label="Expected manufacturer (optional)"><Input aria-label="Expected manufacturer" bind:value={draft.manufacturer} /></Field>
      <Field label="Expected model (optional)"><Input aria-label="Expected model" bind:value={draft.model} /></Field>
      <Field label="Minimum reported processors (0 = no check)"><Input aria-label="Minimum reported processors" type="number" min="0" bind:value={draft.min_cpu_sockets} /></Field>
      <Field label="Minimum memory GiB (0 = no check)"><Input aria-label="Minimum memory GiB" type="number" min="0" bind:value={draft.min_memory_gib} /></Field>
      <Field label="Minimum drives (0 = no check)"><Input aria-label="Minimum drives" type="number" min="0" bind:value={draft.min_drives} /></Field>
      <Field label="Minimum physical NICs (0 = no check)"><Input aria-label="Minimum physical NICs" type="number" min="0" bind:value={draft.min_physical_nics} /></Field>
      <label><input type="checkbox" bind:checked={draft.require_interfaces_documented} /> Require all physical interfaces documented</label>
      <Field label="Expected RAID configuration (optional)"><Input aria-label="Expected RAID configuration" bind:value={draft.raid_expectation} /></Field>
    </fieldset>
    <p>Physical NIC mapping, complete interface documentation and RAID inspection are not yet available; enabling those checks returns unknown.</p>
    {#if editing}<div class="row-actions"><Button size="sm" variant="accent" disabled={busy || !name.trim()} onclick={save}>Save draft</Button>{#if active}<Button size="sm" variant="ghost" disabled={busy || dirty} onclick={publish}>Publish saved draft</Button>{/if}</div>{#if active && dirty}<p>Save changes before publishing.</p>{/if}{/if}
    {#if active?.published_revision && record}<Button size="sm" variant="ghost" disabled={busy} onclick={() => preview(false)}>Preview device #{record.device_id}</Button>{#if editing}<Button size="sm" variant="accent" disabled={busy} onclick={() => preview(true)}>Run and save hardware audit</Button>{/if}{/if}
  {/if}
  {#if audits.length}<details><summary>My saved hardware audits ({audits.length})</summary>{#each audits as audit (audit.id)}<div class="account-row"><span>{new Date(audit.created_at).toLocaleString()} · revision {audit.revision}</span><Button size="sm" variant="ghost" disabled={busy} onclick={() => viewAudit(audit.id)}>View audit</Button></div>{/each}</details>{/if}
  {#if result}
    <p>{resultLabel}: <strong>{result.status}</strong></p>
    {#each result.findings as finding}
      <AuditFinding title={finding.rule} status={finding.status} message={finding.message} source={finding.source || 'Unavailable'} severity={finding.severity} blocksInstall={finding.blocks_install} evidenceAt={finding.evidence_at} values={[{label:'Expected',value:finding.expected},{label:'Observed',value:finding.actual}]} />
    {/each}
  {/if}
</Panel>
