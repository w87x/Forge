<script lang="ts">
  import { onMount } from 'svelte';
  import { Panel, Button, Field, Input } from '@mineral-ui/design';
  import { api } from './api';
  import AuditFinding from './AuditFinding.svelte';
  type Node = {id: string; kind: string; os_name: string; netbox_name: string; mtu: number; parent: string; members: string[]; vlan_id: number;netbox_vlan_id:number};
  type Network = {name: string; interface_id: string; prefix: string; vrf_id: string; allocation_group: string};
  type Graph = {netbox_instance_id:string;nodes: Node[]; networks: Network[]};
  type Profile = {id: string; name: string; environment_id: string; row_version: number; published_revision: number; draft?: Graph; published?: Graph};
  type Issue = {field: string; message: string};
  type Address = {device_id:number; host_key:string; group:string; interface_id:string; vrf_id:string; address:string; prefix:string};
  type Preview = {assignments: Address[]; issues:Issue[]; ignored_hosts:number; hash:string; persisted:boolean};
  type SavedImport = {id:string;profile_id:string;revision:number;addresses:Address[];created_at:string;source_hash:string};
  type AuditResult = {status:string;findings:{rule:string;status:string;message:string;blocks_install:boolean;subject?:string;source?:string;severity?:string;expected?:unknown;actual?:unknown}[]};
  type SavedAudit = {id:string;import_id:string;device_id:number;created_at:string;result?:AuditResult};
  type VRFPage = {results:{id:number;name:string;rd:string}[];count:number;offset:number;has_more:boolean};
  type VLANPage = {results:{id:number;name:string;vid:number;scope:string}[];count:number;offset:number;has_more:boolean};
  let { role, selection, selectedDevices, netboxInstances } = $props<{role: string; selection: {id:string} | null; selectedDevices: {id:number; name:string}[];netboxInstances:{id:string;name:string;base_url:string}[]}>();
  let profiles = $state<Profile[]>([]); let selected = $state(''); let name = $state('');
  let graph = $state<Graph>({netbox_instance_id:'',nodes:[], networks:[]}); let savedGraph = $state(''); let issues = $state<Issue[]>([]); let validated = $state(false); let error = $state(''); let busy = $state(false);
  let active = $derived(profiles.find((p) => p.id === selected));
  let allocationFile = $state<File | null>(null); let preview = $state<Preview | null>(null); let aliases = $state<Record<string,string>>({}); let imports = $state<SavedImport[]>([]);
  let auditDevice = $state(''); let networkAudit = $state<AuditResult|null>(null);
  let savedAudits = $state<SavedAudit[]>([]); let auditLabel = $state('');
  let vrfs = $state<VRFPage|null>(null);
  let vlans = $state<VLANPage|null>(null);let vlanSearch=$state('');
  let previousSelection = $state('');
  let editing = $derived(role === 'full' && !!active?.draft);
  $effect(() => { if ((selection?.id || '') !== previousSelection) { previousSelection=selection?.id || ''; preview=null; aliases={}; imports=[]; auditDevice=''; networkAudit=null; savedAudits=[]; } });
  let dirty = $derived(JSON.stringify(graph) !== savedGraph);
  const json = (body: object): RequestInit => ({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  async function refresh() { try { profiles = await api<Profile[]>('/api/v1/network-profiles'); } catch(e) { error=e instanceof Error ? e.message : 'Could not load network profiles'; } }
  onMount(() => { void refresh(); });
  function load() { const profile=profiles.find((p) => p.id===selected); graph=structuredClone($state.snapshot(profile?.draft || profile?.published || {netbox_instance_id:'',nodes:[],networks:[]})); graph.netbox_instance_id ||= '';for(const node of graph.nodes)node.netbox_vlan_id ||= 0; savedGraph=JSON.stringify(graph); issues=[]; validated=false; preview=null; networkAudit=null; vrfs=null;vlans=null; }
  async function create() { busy=true;error='';try {const p=await api<Profile>('/api/v1/network-profiles',json({name}));name='';await refresh();selected=p.id;load();}catch(e){error=e instanceof Error?e.message:'Could not create profile';}finally{busy=false;} }
  function addNode(kind: string) { graph.nodes.push({id:crypto.randomUUID(),kind,os_name:'',netbox_name:'',mtu:0,parent:'',members:[],vlan_id:kind==='vlan'?1:0,netbox_vlan_id:0}); }
  function addNetwork() { graph.networks.push({name:'',interface_id:'',prefix:'',vrf_id:'',allocation_group:''}); }
  async function loadVRFs(offset=0){if(!graph.netbox_instance_id)return;const id=graph.netbox_instance_id;busy=true;error='';try{const page=await api<VRFPage>(`/api/v1/netbox/instances/${encodeURIComponent(id)}/vrfs?offset=${offset}`);if(graph.netbox_instance_id===id)vrfs=page;}catch(e){error=e instanceof Error?e.message:'Could not load VRFs';}finally{busy=false;}}
  async function loadVLANs(offset=0){if(!graph.netbox_instance_id)return;const id=graph.netbox_instance_id,search=vlanSearch;busy=true;error='';try{const query=new URLSearchParams({offset:String(offset),q:search});const page=await api<VLANPage>(`/api/v1/netbox/instances/${encodeURIComponent(id)}/vlans?${query}`);if(graph.netbox_instance_id===id && vlanSearch===search)vlans=page;}catch(e){error=e instanceof Error?e.message:'Could not load VLANs';}finally{busy=false;}}
  function chooseVLAN(node:Node,id:string){node.netbox_vlan_id=Number(id);const vlan=vlans?.results.find((item)=>item.id===node.netbox_vlan_id);if(vlan)node.vlan_id=vlan.vid;}
  function toggleMember(node: Node, id: string, checked: boolean) { node.members=checked?[...node.members,id]:node.members.filter((member)=>member!==id); }
  async function validate(id: string) { issues=await api<Issue[]>(`/api/v1/network-profiles/${encodeURIComponent(id)}/validation`); validated=true; }
  async function save() { if(!active) return;busy=true;error='';try {const p=await api<Profile>(`/api/v1/network-profiles/${encodeURIComponent(active.id)}/draft`,{...json({row_version:active.row_version,graph:$state.snapshot(graph)}),method:'PUT'});await refresh();selected=p.id;load();await validate(p.id);}catch(e){error=e instanceof Error?e.message:'Could not save draft';}finally{busy=false;} }
  async function publish() { if(!active) return;busy=true;error='';try {await api(`/api/v1/network-profiles/${encodeURIComponent(active.id)}/publish`,json({row_version:active.row_version}));await refresh();load();await validate(active.id);}catch(e){error=e instanceof Error?e.message:'Could not publish draft';if(active)try{await validate(active.id);}catch{/* preserve publish error */}}finally{busy=false;} }
  async function loadImports() { if(!selection)return; const selectionID=selection.id;try {const [items,audits]=await Promise.all([api<SavedImport[]>(`/api/v1/allocation-imports?selection_id=${encodeURIComponent(selectionID)}`),api<SavedAudit[]>(`/api/v1/network-audits?selection_id=${encodeURIComponent(selectionID)}`)]);if(selection?.id===selectionID){imports=items;savedAudits=audits;}}catch(e){error=e instanceof Error?e.message:'Could not load saved imports';} }
  async function previewAllocation(save = false) {
    if(!active || !selection || !allocationFile)return;
    if(allocationFile.size>2*1024*1024){error='Allocation file must be 2 MiB or smaller';return;}
    busy=true;error='';preview=null;
    const profileID=active.id, revision=active.published_revision, selectionID=selection.id, file=allocationFile;
    const aliasSnapshot=Object.fromEntries(Object.entries($state.snapshot(aliases)).filter(([,value]) => value !== '')); const aliasHash=JSON.stringify(aliasSnapshot);
    try { const endpoint=save?'allocation-imports':'allocation-preview';const result=await api<Preview>(`/api/v1/network-profiles/${encodeURIComponent(profileID)}/${endpoint}`,json({selection_id:selectionID,revision,content:await file.text(),aliases:aliasSnapshot})); if(selection?.id===selectionID && active?.id===profileID && active.published_revision===revision && allocationFile===file && JSON.stringify(Object.fromEntries(Object.entries($state.snapshot(aliases)).filter(([,value]) => value !== '')))===aliasHash) preview=result;if(save)await loadImports(); }
    catch(e){error=e instanceof Error?e.message:'Could not preview allocations';}finally{busy=false;}
  }
  async function auditImport(item:SavedImport,save=false) {
    if(!selection || !auditDevice)return;const selectionID=selection.id,deviceID=auditDevice,profileID=item.profile_id;busy=true;error='';networkAudit=null;
    try{const path=save?'audits':'audit-preview';const result=await api<AuditResult|SavedAudit>(`/api/v1/network-profiles/${encodeURIComponent(profileID)}/${path}`,json({selection_id:selectionID,import_id:item.id,device_id:Number(deviceID)}));if(selection?.id===selectionID && auditDevice===deviceID && selected===profileID){networkAudit=save?(result as SavedAudit).result||null:result as AuditResult;auditLabel=save?'Saved network check':'Network assignment preview';}if(save)await loadImports();}
    catch(e){error=e instanceof Error?e.message:'Could not check network assignments';}finally{busy=false;}
  }
  async function viewSavedAudit(item:SavedAudit){if(!selection)return;const selectionID=selection.id,profileID=selected;busy=true;error='';try{const loaded=await api<SavedAudit>(`/api/v1/network-audits/${encodeURIComponent(item.id)}?selection_id=${encodeURIComponent(selectionID)}`);if(selection?.id===selectionID && selected===profileID){networkAudit=loaded.result||null;auditLabel=`Saved network check · ${new Date(loaded.created_at).toLocaleString()}`;}}catch(e){error=e instanceof Error?e.message:'Could not load network check';}finally{busy=false;}}
</script>

<Panel title="Network profiles">
  <p>Define interfaces and networks with forms. Published profiles can be used for read-only network checks; NetBox changes are not yet available.</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if role === 'full'}<form onsubmit={(event)=>{event.preventDefault();void create();}}>
    <Field label="New profile name"><Input aria-label="New network profile name" bind:value={name} required /></Field>
    <Button type="submit" size="sm" variant="accent" disabled={busy}>Create network profile</Button>
  </form>{/if}
  <label for="network-profile">Profile</label><select id="network-profile" bind:value={selected} onchange={load}><option value="">Choose profile</option>{#each profiles as p (p.id)}<option value={p.id}>{p.name}{profiles.filter((other) => other.name === p.name).length > 1 ? ` · ${p.id.slice(0, 8)}` : ''} · {p.published_revision ? `revision ${p.published_revision}` : 'draft'}</option>{/each}</select>
  <Button size="sm" variant="ghost" disabled={busy} onclick={refresh}>Refresh profiles</Button>
  {#if active}
    <p>Draft version {active.row_version} · published revision {active.published_revision || 'none'} · NetBox references unverified</p>
    <label for="network-netbox">NetBox connection for VLAN and VRF references</label><select id="network-netbox" bind:value={graph.netbox_instance_id} disabled={!editing} onchange={() => { for(const item of graph.networks)item.vrf_id='';for(const node of graph.nodes)node.netbox_vlan_id=0; vrfs=null;vlans=null; }}><option value="">No specific connection (global VRF only)</option>{#each netboxInstances as instance (instance.id)}<option value={instance.id}>{instance.name} · {instance.base_url}</option>{/each}</select>
    {#if graph.netbox_instance_id && editing}<div class="row-actions"><Button size="sm" variant="ghost" disabled={busy} onclick={() => loadVRFs()}>Load VRFs with my NetBox key</Button>{#if vrfs}<Button size="sm" variant="ghost" disabled={busy || vrfs.offset===0} onclick={() => loadVRFs(Math.max(0,vrfs!.offset-50))}>Previous VRFs</Button><Button size="sm" variant="ghost" disabled={busy || !vrfs.has_more} onclick={() => loadVRFs(vrfs!.offset+vrfs!.results.length)}>Next VRFs</Button>{/if}</div>{/if}
    {#if graph.netbox_instance_id && editing}<label for="vlan-search">Search NetBox VLANs</label><input id="vlan-search" bind:value={vlanSearch} oninput={() => {vlans=null;}} /><div class="row-actions"><Button size="sm" variant="ghost" disabled={busy} onclick={() => loadVLANs()}>Load VLANs with my NetBox key</Button>{#if vlans}<Button size="sm" variant="ghost" disabled={busy || vlans.offset===0} onclick={() => loadVLANs(Math.max(0,vlans!.offset-50))}>Previous VLANs</Button><Button size="sm" variant="ghost" disabled={busy || !vlans.has_more} onclick={() => loadVLANs(vlans!.offset+vlans!.results.length)}>Next VLANs</Button>{/if}</div>{/if}
    {#if editing}<div class="row-actions"><Button size="sm" variant="ghost" onclick={() => addNode('physical')}>Add physical</Button><Button size="sm" variant="ghost" onclick={() => addNode('bond')}>Add bond</Button><Button size="sm" variant="ghost" onclick={() => addNode('vlan')}>Add VLAN</Button><Button size="sm" variant="ghost" onclick={() => addNode('bridge')}>Add bridge</Button></div>{/if}
    {#each graph.nodes as node, index (node.id)}
      <fieldset disabled={!editing}><legend>{node.kind} · {node.os_name || 'unnamed interface'}</legend>
        <label>Linux name <input bind:value={node.os_name} /></label><label>NetBox name <input bind:value={node.netbox_name} /></label><label>MTU (0 = unspecified) <input type="number" min="0" max="65535" bind:value={node.mtu} /></label>
        {#if node.kind === 'vlan'}<label>VLAN ID <input type="number" min="1" max="4094" bind:value={node.vlan_id} /></label><label>NetBox VLAN <select value={String(node.netbox_vlan_id)} onchange={(event) => chooseVLAN(node,event.currentTarget.value)}><option value="0">Not selected</option>{#if node.netbox_vlan_id && !vlans?.results.some((vlan) => vlan.id===node.netbox_vlan_id)}<option value={String(node.netbox_vlan_id)}>Selected VLAN #{node.netbox_vlan_id} (not in loaded page)</option>{/if}{#each vlans?.results || [] as vlan (vlan.id)}<option value={String(vlan.id)}>{vlan.name || 'Unnamed'} · VLAN {vlan.vid} · {vlan.scope || 'global'} · #{vlan.id}</option>{/each}</select></label><label>Parent <select bind:value={node.parent}><option value="">Choose parent</option>{#each graph.nodes.filter((item) => item.id !== node.id && ['physical','bond'].includes(item.kind)) as parent (parent.id)}<option value={parent.id}>{parent.os_name || 'unnamed'} · {parent.kind}</option>{/each}</select></label>{/if}
        {#if node.kind === 'bond' || node.kind === 'bridge'}<p>Members</p>{#each graph.nodes.filter((item) => item.id !== node.id && (node.kind === 'bond' ? item.kind === 'physical' : ['physical','bond','vlan'].includes(item.kind))) as member (member.id)}<label><input type="checkbox" checked={node.members.includes(member.id)} onchange={(event) => toggleMember(node,member.id,event.currentTarget.checked)} /> {member.os_name || 'unnamed'} · {member.kind}</label>{/each}{/if}
        {#if editing}<Button size="sm" variant="ghost" onclick={() => { graph.nodes.splice(index,1); }}>Remove interface</Button>{/if}
      </fieldset>
    {/each}
    {#if editing}<Button size="sm" variant="ghost" onclick={addNetwork}>Add network</Button>{/if}
    {#each graph.networks as network, index}
      <fieldset disabled={!editing}><legend>Network · {network.name || 'unnamed'}</legend>
        <label>Name <input bind:value={network.name} /></label><label>Interface <select bind:value={network.interface_id}><option value="">Choose interface</option>{#each graph.nodes as node (node.id)}<option value={node.id}>{node.os_name || 'unnamed'} · {node.kind}</option>{/each}</select></label>
        <label>Prefix <input bind:value={network.prefix} placeholder="192.0.2.0/24" /></label><label>Allocation group <input bind:value={network.allocation_group} placeholder="ctl_ips" /></label><label>VRF <select bind:value={network.vrf_id}><option value="">Global routing table</option>{#if network.vrf_id && !vrfs?.results.some((vrf) => String(vrf.id)===network.vrf_id)}<option value={network.vrf_id}>Selected VRF #{network.vrf_id} (not in loaded page)</option>{/if}{#each vrfs?.results || [] as vrf (vrf.id)}<option value={String(vrf.id)}>{vrf.name || 'Unnamed'} · {vrf.rd || 'no RD'} · #{vrf.id}</option>{/each}</select></label>
        {#if editing}<Button size="sm" variant="ghost" onclick={() => { graph.networks.splice(index,1); }}>Remove network</Button>{/if}
      </fieldset>
    {/each}
    {#if editing}<div class="row-actions"><Button size="sm" variant="accent" disabled={busy} onclick={save}>Save and validate draft</Button><Button size="sm" variant="ghost" disabled={busy || dirty} onclick={publish}>Publish saved draft</Button></div>{#if dirty}<p>Save changes before publishing.</p>{/if}{/if}
    {#if issues.length}<p>Validation of last saved draft:</p><ul>{#each issues as issue}<li>{issue.field}: {issue.message}</li>{/each}</ul>{:else if editing && validated}<p>No validation errors reported for the last saved draft.</p>{/if}
    {#if active.published_revision}
      <div class="section-form"><strong>Allocation import</strong><p>Upload a Kayobe-style allocation file. Only selected devices are stored. NetBox conflicts are not yet checked.</p>
        {#if !selection}<p>Freeze a NetBox device selection first.</p>{:else}<label for="allocation-file">Allocation file</label><input id="allocation-file" type="file" accept=".yml,.yaml,text/yaml,application/yaml" onchange={(event) => { allocationFile=event.currentTarget.files?.[0] || null; preview=null; }} /><details><summary>Host key overrides</summary><p>Leave blank to match the NetBox device name exactly.</p>{#each selectedDevices as device (device.id)}<label>{device.name || `Device #${device.id}`} <input aria-label={`Allocation host key for ${device.name || device.id}`} value={aliases[String(device.id)] || ''} oninput={(event) => { aliases[String(device.id)]=event.currentTarget.value; preview=null; }} /></label>{/each}</details><Button size="sm" variant="ghost" disabled={busy || !allocationFile} onclick={() => previewAllocation(false)}>Preview allocations</Button><Button size="sm" variant="ghost" disabled={busy} onclick={loadImports}>Load saved imports for selection</Button>{/if}
        {#if preview}<p>Ignored {preview.ignored_hosts} unselected hosts · NetBox conflicts not checked{preview.persisted ? ' · saved' : ''}</p>{#each preview.assignments as assignment}<div class="account-row"><span>Device #{assignment.device_id} · {assignment.host_key} · {assignment.group}</span><span>{assignment.address} · {assignment.vrf_id || 'global VRF'} · {assignment.prefix}</span></div>{/each}{#each preview.issues as issue}<p class="error">{issue.field}: {issue.message}</p>{/each}{#if role === 'full' && !preview.issues.length && !preview.persisted}<Button size="sm" variant="accent" disabled={busy} onclick={() => previewAllocation(true)}>Save import</Button>{/if}{/if}
        {#if imports.some((item) => item.profile_id === active.id)}<label for="network-audit-device">Check one selected device</label><select id="network-audit-device" bind:value={auditDevice} onchange={() => { networkAudit=null; }}><option value="">Choose device</option>{#each selectedDevices as device (device.id)}<option value={String(device.id)}>{device.name || device.id}</option>{/each}</select>{/if}
        {#each imports.filter((item) => item.profile_id === active.id) as item (item.id)}<details><summary>Saved {new Date(item.created_at).toLocaleString()} · profile revision {item.revision}</summary><p>Source hash {item.source_hash} · NetBox conflicts not checked</p>{#each item.addresses as address}<div class="account-row"><span>Device #{address.device_id} · {address.group}</span><span>{address.address} · {address.vrf_id || 'global VRF'}</span></div>{/each}<Button size="sm" variant="ghost" disabled={busy || !auditDevice} onclick={() => auditImport(item)}>Preview visible assignments</Button>{#if role === 'full'}<Button size="sm" variant="accent" disabled={busy || !auditDevice} onclick={() => auditImport(item,true)}>Run and save network check</Button>{/if}{#each savedAudits.filter((audit) => audit.import_id===item.id) as audit (audit.id)}<div class="account-row"><span>Device #{audit.device_id} · {new Date(audit.created_at).toLocaleString()}</span><Button size="sm" variant="ghost" disabled={busy} onclick={() => viewSavedAudit(audit)}>View saved check</Button></div>{/each}</details>{/each}
        {#if networkAudit}<p>{auditLabel}: <strong>{networkAudit.status}</strong></p>{#each networkAudit.findings as finding}<AuditFinding title={finding.subject || finding.rule} status={finding.status} message={finding.message} source={finding.source || 'Unavailable'} severity={finding.severity} blocksInstall={finding.blocks_install} values={[{label:'Rule',value:finding.rule},{label:'Expected',value:finding.expected},{label:'Observed',value:finding.actual}]} />{/each}{/if}
      </div>
    {/if}
  {/if}
</Panel>
