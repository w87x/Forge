<script lang="ts">
  import { onMount } from 'svelte';
  import { Panel, Button } from '@mineral-ui/design';
  import { api } from './api';
  import AuditFinding from './AuditFinding.svelte';
  type Finding={rule:string;status:string;message:string;blocks_install:boolean;subject?:string;source?:string;severity?:string;evidence_at?:string;expected?:unknown;actual?:unknown};
  type HardwareAudit={id:string;profile_id:string;revision:number;job_id:string;created_at:string};
  type NetworkAudit={id:string;import_id:string;device_id:number;created_at:string};
  type Profile={id:string;name:string;published_revision:number};
  type Result={status:string;hardware:{status:string;findings:Finding[]};network:{status:string;findings:Finding[]};hardware_profile_id:string;hardware_revision:number;network_profile_id:string;network_revision:number;allocation_hash:string;bios?:{status:string;reason?:string;findings:{attribute:string;status:string;expected:unknown;active:unknown;pending:unknown;pending_status:string}[]};bios_profile_id?:string;bios_revision?:number;hardware_evidence_at:string;network_checked_at:string;freshness:string[]};
  type Audit={id:string;hardware_audit_id:string;network_audit_id:string;job_id:string;created_at:string;result?:Result;current_freshness:string[]};
  type Investigation={id:string;audit_id:string;created_at:string;current_freshness:string[];row_version:number;completed:string[];tasks:{id:string;category:string;rule:string;status:string;message:string}[]};
  let {role,selection,openInspection}=$props<{role:string;selection:{id:string}|null;openInspection:(id:string)=>void}>();
  let hardware=$state<HardwareAudit[]>([]);let networks=$state<NetworkAudit[]>([]);let profiles=$state<Profile[]>([]);let biosProfiles=$state<Profile[]>([]);let audits=$state<Audit[]>([]);
  let hardwareID=$state('');let networkID=$state('');let biosID=$state('');let previousSelection=$state('');let busy=$state(false);let error=$state('');let result=$state<Result|null>(null);let label=$state('');
  let currentFreshness=$state<string[]>([]);
  let inspectionJob=$state('');
  let auditID=$state('');let investigations=$state<Investigation[]>([]);
  let category=$state('all');let findingStatus=$state('all');let findingSeverity=$state('all');let findingSearch=$state('');
  function matches(status:string,...fields:unknown[]){const q=findingSearch.trim().toLowerCase();return (findingStatus==='all'||status===findingStatus)&&(!q||fields.some((field)=>String(field??'').toLowerCase().includes(q)));}
  function severityMatches(severity?:string){return findingSeverity==='all'||(severity || 'unavailable')===findingSeverity;}
  const json=(body:object):RequestInit=>({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  function profileName(id:string){return profiles.find((p:Profile)=>p.id===id)?.name||'Hardware profile';}
  async function refresh(){try{[hardware,profiles,biosProfiles,audits]=await Promise.all([api<HardwareAudit[]>('/api/v1/hardware-audits'),api<Profile[]>('/api/v1/hardware-profiles'),api<Profile[]>('/api/v1/bios-profiles'),api<Audit[]>('/api/v1/audits')]);}catch(e){error=e instanceof Error?e.message:'Could not load audits';}}
  async function loadNetwork(selectionID:string){try{const items=await api<NetworkAudit[]>(`/api/v1/network-audits?selection_id=${encodeURIComponent(selectionID)}`);if(selection?.id===selectionID)networks=items;}catch(e){if(selection?.id===selectionID)error=e instanceof Error?e.message:'Could not load network checks';}}
  onMount(()=>{void refresh();});
  $effect(()=>{const id=selection?.id||'';if(id!==previousSelection){previousSelection=id;networks=[];networkID='';result=null;inspectionJob='';auditID='';investigations=[];currentFreshness=[];if(id)void loadNetwork(id);}});
  async function investigationsFor(create=false){if(!selection || !auditID)return;const selected=selection.id,id=auditID;busy=true;error='';try{if(create)await api(`/api/v1/audits/${encodeURIComponent(id)}/investigations`,json({selection_id:selected}));const list=await api<Investigation[]>(`/api/v1/audits/${encodeURIComponent(id)}/investigations?selection_id=${encodeURIComponent(selected)}`);if(selection?.id===selected&&auditID===id)investigations=list;}catch(e){error=e instanceof Error?e.message:'Could not load investigation tasks';}finally{busy=false;}}
  async function setTaskDone(item:Investigation,taskID:string,checked:boolean){if(!selection)return;const selected=selection.id,id=auditID,completed=checked?[...item.completed,taskID]:item.completed.filter((value)=>value!==taskID);busy=true;error='';try{const updated=await api<Investigation>(`/api/v1/investigations/${encodeURIComponent(item.id)}/progress`,{...json({selection_id:selected,row_version:item.row_version,completed}),method:'PUT'});if(selection?.id===selected&&auditID===id)investigations=investigations.map((value)=>value.id===item.id?updated:value);}catch(e){error=e instanceof Error?e.message:'Could not update investigation progress';}finally{busy=false;}}
  async function run(){if(!selection || !hardwareID || !networkID)return;const selected=selection.id,revision=biosID?(biosProfiles.find((p)=>p.id===biosID)?.published_revision||0):0;busy=true;error='';try{const item=await api<Audit>('/api/v1/audits',json({hardware_audit_id:hardwareID,network_audit_id:networkID,selection_id:selected,bios_profile_id:biosID,bios_revision:revision}));if(selection?.id===selected){result=item.result||null;auditID=item.id;investigations=[];inspectionJob=item.job_id;currentFreshness=item.current_freshness||[];label=`Saved ${new Date(item.created_at).toLocaleString()}`;}await refresh();}catch(e){error=e instanceof Error?e.message:'Could not create combined audit';}finally{busy=false;}}
  async function view(id:string){if(!selection)return;const selected=selection.id;busy=true;error='';try{const item=await api<Audit>(`/api/v1/audits/${encodeURIComponent(id)}?selection_id=${encodeURIComponent(selected)}`);if(selection?.id===selected){result=item.result||null;auditID=item.id;investigations=[];inspectionJob=item.job_id;currentFreshness=item.current_freshness||[];label=`Saved ${new Date(item.created_at).toLocaleString()}`;}}catch(e){error=e instanceof Error?e.message:'Could not open audit';}finally{busy=false;}}
</script>

<Panel title="Combined audits">
  <p>Combine saved hardware and network checks for the same device, with an optional BIOS profile. Results retain their evidence and profile revisions.</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if !selection}<p>Freeze a current selection of the same devices to create or open an audit.</p>{:else if role==='full'}
    <label for="combined-hardware">Hardware check</label><select id="combined-hardware" bind:value={hardwareID}><option value="">Choose saved hardware check</option>{#each hardware as item (item.id)}<option value={item.id}>{profileName(item.profile_id)} · revision {item.revision} · {new Date(item.created_at).toLocaleString()}</option>{/each}</select>
    <label for="combined-network">Network check</label><select id="combined-network" bind:value={networkID}><option value="">Choose saved network check</option>{#each networks as item (item.id)}<option value={item.id}>Device #{item.device_id} · {new Date(item.created_at).toLocaleString()}</option>{/each}</select>
    <label for="combined-bios">BIOS profile (optional)</label><select id="combined-bios" bind:value={biosID}><option value="">No BIOS check</option>{#each biosProfiles.filter((p)=>p.published_revision>0) as p (p.id)}<option value={p.id}>{p.name} · revision {p.published_revision}</option>{/each}</select>
    <div class="row-actions"><Button size="sm" variant="ghost" disabled={busy} onclick={() => {void refresh();if(selection)void loadNetwork(selection.id);}}>Refresh checks</Button><Button size="sm" variant="accent" disabled={busy || !hardwareID || !networkID} onclick={run}>Run combined audit</Button></div>
  {/if}
  {#if audits.length}<details><summary>My combined audits ({audits.length})</summary>{#each audits as item (item.id)}<div class="account-row"><span>{new Date(item.created_at).toLocaleString()}</span><Button size="sm" variant="ghost" disabled={busy || !selection} onclick={() => view(item.id)}>View audit</Button></div>{/each}</details>{/if}
  {#if result}
    <p>{label} · status when saved <strong>{result.status}</strong></p>
    {#if inspectionJob}<Button size="sm" variant="ghost" onclick={() => openInspection(inspectionJob)}>Open source inspection</Button>{/if}
    <p>Hardware evidence: {new Date(result.hardware_evidence_at).toLocaleString()} · network checked: {new Date(result.network_checked_at).toLocaleString()}</p>
    {#each currentFreshness as warning}<p class="error">Current evidence: {warning}</p>{/each}
    <div class="section-form">
      <strong>Investigation tasks</strong>
      <p>These tasks identify findings for operator review. Checkboxes track operator review only; they do not propose or execute NetBox changes.</p>
      <div class="row-actions"><Button size="sm" variant="ghost" disabled={busy} onclick={() => investigationsFor(false)}>Load tasks</Button>{#if role==='full'}<Button size="sm" variant="ghost" disabled={busy} onclick={() => investigationsFor(true)}>Create task list</Button>{/if}</div>
      {#each investigations as investigation (investigation.id)}<details><summary>Created {new Date(investigation.created_at).toLocaleString()} · {investigation.tasks.length} tasks</summary>{#each investigation.current_freshness || [] as warning}<p class="error">Current evidence: {warning}</p>{/each}{#each investigation.tasks as task (task.id)}<div class="account-row"><label><input type="checkbox" checked={investigation.completed.includes(task.id)} disabled={busy || role!=='full'} onchange={(event)=>{const checked=event.currentTarget.checked;event.currentTarget.checked=!checked;void setTaskDone(investigation,task.id,checked);}} /> {task.category} · {task.rule} · {task.status}</label><span>{task.message}</span></div>{:else}<p>No investigation findings in this audit.</p>{/each}</details>{/each}
    </div>
    <div class="audit-filters">
      <label>Category <select bind:value={category}><option value="all">All categories</option><option value="hardware">Hardware</option><option value="network">Network</option><option value="bios">BIOS</option></select></label>
      <label>Status <select bind:value={findingStatus}><option value="all">All statuses</option><option value="pass">Pass</option><option value="fail">Fail</option><option value="unknown">Unknown</option></select></label>
      <label>Severity <select bind:value={findingSeverity}><option value="all">All severities</option><option value="error">Error</option><option value="warning">Warning</option><option value="info">Info</option><option value="unavailable">Unavailable</option></select></label>
      <label>Search findings <input type="search" bind:value={findingSearch} placeholder="Rule, subject or message" /></label>
    </div>
    {#if category==='all' || category==='hardware'}
      <details open><summary>Hardware · {result.hardware.status} · revision {result.hardware_revision}</summary>
        <p>{profileName(result.hardware_profile_id)}</p>
        {#each result.hardware.findings.filter((f)=>severityMatches(f.severity)&&matches(f.status,f.rule,f.message,f.source,f.expected,f.actual)) as finding}
          <AuditFinding title={finding.rule} status={finding.status} message={finding.message} source={finding.source || 'Unavailable'} severity={finding.severity} blocksInstall={finding.blocks_install} evidenceAt={finding.evidence_at} values={[{label:'Expected',value:finding.expected},{label:'Observed',value:finding.actual}]} />
        {:else}<p>No matching hardware findings.</p>{/each}
      </details>
    {/if}
    {#if category==='all' || category==='network'}
      <details open><summary>Network · {result.network.status} · revision {result.network_revision}</summary>
        <p>Allocation source hash {result.allocation_hash}</p>
        {#each result.network.findings.filter((f)=>severityMatches(f.severity)&&matches(f.status,f.rule,f.subject,f.message,f.source,f.expected,f.actual)) as finding}
          <AuditFinding title={finding.subject || finding.rule} status={finding.status} message={finding.message} source={finding.source || 'Unavailable'} severity={finding.severity} blocksInstall={finding.blocks_install} evidenceAt={result.network_checked_at} evidenceLabel="Network check saved" values={[{label:'Rule',value:finding.rule},{label:'Expected',value:finding.expected},{label:'Observed',value:finding.actual}]} />
        {:else}<p>No matching network findings.</p>{/each}
      </details>
    {/if}
    {#if category==='bios' && !result.bios}<p>This audit has no BIOS check.</p>{/if}
    {#if result.bios && (category==='all' || category==='bios')}
      <details open><summary>BIOS · {result.bios.status} · revision {result.bios_revision}</summary>
        {#if result.bios.reason}<p>{result.bios.reason}</p>{/if}
        {#each result.bios.findings.filter((f)=>severityMatches()&&matches(f.status,f.attribute,f.expected,f.active,f.pending)) as finding}
          <AuditFinding title={finding.attribute} status={finding.status} source="Redfish BIOS inspection" evidenceAt={result.hardware_evidence_at} values={[{label:'Expected',value:finding.expected},{label:'Active',value:finding.active},{label:'Pending',value:finding.pending},{label:'Pending comparison',value:finding.pending_status}]} />
        {:else}<p>No matching BIOS findings.</p>{/each}
      </details>
    {/if}
  {/if}
</Panel>
