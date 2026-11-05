<script lang="ts">
  import {onMount} from 'svelte';
  import {Panel,Button,Field,Input} from '@mineral-ui/design';
  import {api} from './api';
  type Spec={netbox_instance_id:string;switches:{device_id:number;fabric:string}[];preferred_racks:number[];allow_same_site:boolean;distinct_switches:boolean;distinct_fabrics:boolean;requirements:{id:string;speed_mbps:number;media:string;port_role:string;fabric:string}[]};
  type Profile={id:string;name:string;row_version:number;published_revision:number;draft?:Spec;published?:Spec};
  let {role,netboxInstances}=$props<{role:string;netboxInstances:{id:string;name:string;base_url:string}[]}>();
  let profiles=$state<Profile[]>([]), selected=$state(''), name=$state(''), busy=$state(false), error=$state(''), saved=$state('');
  const empty=():Spec=>({netbox_instance_id:'',switches:[],preferred_racks:[],allow_same_site:false,distinct_switches:false,distinct_fabrics:false,requirements:[]});
  let spec=$state<Spec>(empty());let active=$derived(profiles.find(p=>p.id===selected));let editing=$derived(role==='full' && !!active?.draft);let dirty=$derived(JSON.stringify(spec)!==saved);
  const json=(body:object):RequestInit=>({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  function choose(){const p=profiles.find(p=>p.id===selected);spec=structuredClone($state.snapshot(p?.draft||p?.published||empty()));spec.switches ||= [];spec.preferred_racks ||= [];spec.requirements ||= [];saved=JSON.stringify(spec);}
  async function refresh(){profiles=await api<Profile[]>('/api/v1/cabling-profiles');}
  onMount(()=>{void refresh().catch(e=>error=e instanceof Error?e.message:'Could not load cabling profiles');});
  async function create(){busy=true;error='';try{const p=await api<Profile>('/api/v1/cabling-profiles',json({name}));name='';await refresh();selected=p.id;choose();}catch(e){error=e instanceof Error?e.message:'Could not create profile';}finally{busy=false;}}
  async function save(){if(!active)return;busy=true;error='';try{await api(`/api/v1/cabling-profiles/${encodeURIComponent(active.id)}/draft`,{...json({row_version:active.row_version,profile:$state.snapshot(spec)}),method:'PUT'});await refresh();choose();}catch(e){error=e instanceof Error?e.message:'Could not save draft';}finally{busy=false;}}
  async function publish(){if(!active)return;busy=true;error='';try{await api(`/api/v1/cabling-profiles/${encodeURIComponent(active.id)}/publish`,json({row_version:active.row_version}));await refresh();choose();}catch(e){error=e instanceof Error?e.message:'Could not publish profile';}finally{busy=false;}}
</script>
<Panel title="Cabling policies">
  <p>Define switch, rack and port preferences for future cable planning. NetBox references are not verified and planning is not yet connected.</p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if role==='full'}<form onsubmit={(event)=>{event.preventDefault();void create();}}><Field label="New policy name"><Input aria-label="New cabling policy name" bind:value={name} required /></Field><Button type="submit" size="sm" disabled={busy}>Create policy</Button></form>{/if}
  <label for="cabling-profile">Policy</label><select id="cabling-profile" bind:value={selected} onchange={choose}><option value="">Choose policy</option>{#each profiles as p (p.id)}<option value={p.id}>{p.name} · {p.published_revision?`revision ${p.published_revision}`:'draft'}</option>{/each}</select>
  {#if active}
    <p>Draft version {active.row_version} · published revision {active.published_revision||'none'}</p>
    <fieldset disabled={!editing}>
      <label for="cabling-netbox">NetBox connection</label><select id="cabling-netbox" bind:value={spec.netbox_instance_id} onchange={() => {spec.switches=[];spec.preferred_racks=[];}}><option value="">Choose connection</option>{#each netboxInstances as instance (instance.id)}<option value={instance.id}>{instance.name}</option>{/each}</select>
      <p>Switches (NetBox device IDs)</p>
      {#each spec.switches as item,i}<div class="account-row"><label>Device ID <input type="number" min="1" bind:value={item.device_id} /></label><label>Fabric <input bind:value={item.fabric} /></label>{#if editing}<Button size="sm" variant="ghost" onclick={()=>spec.switches.splice(i,1)}>Remove</Button>{/if}</div>{/each}
      {#if editing}<Button size="sm" variant="ghost" onclick={()=>spec.switches.push({device_id:0,fabric:''})}>Add switch</Button>{/if}
      <p>Preferred rack IDs, in order after the server's rack</p>
      {#each spec.preferred_racks as rack,i}<div class="account-row"><label>Rack ID <input type="number" min="1" value={rack} onchange={(event)=>spec.preferred_racks[i]=Number(event.currentTarget.value)} /></label>{#if editing}<Button size="sm" variant="ghost" onclick={()=>spec.preferred_racks.splice(i,1)}>Remove</Button>{/if}</div>{/each}
      {#if editing}<Button size="sm" variant="ghost" onclick={()=>spec.preferred_racks.push(0)}>Add rack</Button>{/if}
      <label><input type="checkbox" bind:checked={spec.allow_same_site} /> Allow other racks in the same site</label>
      <label><input type="checkbox" bind:checked={spec.distinct_switches} /> Use distinct switches</label>
      <label><input type="checkbox" bind:checked={spec.distinct_fabrics} /> Use distinct fabrics</label>
      <p>Port requirements</p>
      {#each spec.requirements as item,i}<fieldset><legend>Requirement {i+1}</legend><label>Name <input bind:value={item.id} /></label><label>Speed (Mbps) <input type="number" min="1" bind:value={item.speed_mbps} /></label><label>Media <input bind:value={item.media} placeholder="sfp+" /></label><label>Port role <input bind:value={item.port_role} /></label><label>Required fabric (optional) <input bind:value={item.fabric} /></label>{#if editing}<Button size="sm" variant="ghost" onclick={()=>spec.requirements.splice(i,1)}>Remove requirement</Button>{/if}</fieldset>{/each}
      {#if editing}<Button size="sm" variant="ghost" onclick={()=>spec.requirements.push({id:'',speed_mbps:0,media:'',port_role:'',fabric:''})}>Add requirement</Button>{/if}
    </fieldset>
    {#if editing}<div class="row-actions"><Button size="sm" variant="accent" disabled={busy} onclick={save}>Save draft</Button><Button size="sm" variant="ghost" disabled={busy||dirty} onclick={publish}>Publish saved draft</Button></div>{#if dirty}<p>Save changes before publishing.</p>{/if}{/if}
  {/if}
</Panel>
