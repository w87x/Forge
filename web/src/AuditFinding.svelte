<script lang="ts">
  type ValueRow = {label:string; value:unknown};
  let {title,status,message,source,severity,blocksInstall,evidenceAt,evidenceLabel='Evidence collected',values=[]} = $props<{
    title:string; status:string; message?:string; source?:string; severity?:string;
    blocksInstall?:boolean; evidenceAt?:string; evidenceLabel?:string; values?:ValueRow[];
  }>();
  function display(value:unknown):string {
    if (value === null || value === undefined) return 'Unavailable';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
  }
  function date(value:string):string {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? 'Unavailable' : parsed.toLocaleString();
  }
</script>

<details class="finding-detail">
  <summary><span>{title}</span><span>{status}</span></summary>
  {#if message}<p>{message}</p>{/if}
  <dl>
    {#if source}<dt>Source</dt><dd>{source}</dd>{/if}
    {#if severity}<dt>Severity</dt><dd>{severity}</dd>{/if}
    {#if blocksInstall !== undefined}<dt>Installation policy</dt><dd>{blocksInstall ? 'Blocks installation' : 'Does not block installation'}</dd>{/if}
    {#if evidenceAt}<dt>{evidenceLabel}</dt><dd>{date(evidenceAt)}</dd>{/if}
    {#each values as item}
      <dt>{item.label}</dt><dd><pre>{display(item.value)}</pre></dd>
    {/each}
  </dl>
</details>
