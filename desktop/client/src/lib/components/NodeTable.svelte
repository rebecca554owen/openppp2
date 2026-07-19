<script>
  import { Star } from 'lucide-svelte'
  import { latencyTone } from '../runtime/model.js'
  export let nodes = []
  export let currentNodeId = null
  export let runtime
  export let showFavorite = false
</script>

<div class="table-scroll">
  <table>
    <thead><tr>{#if showFavorite}<th class="fav"></th>{/if}<th>名称</th><th>副标题</th><th class="address">地址</th><th class="latency">延迟</th><th class="action"></th></tr></thead>
    <tbody>
      {#each nodes as node (node.id)}
        <tr class:current={node.id === currentNodeId}>
          {#if showFavorite}<td class="fav"><button class:active={node.favorite} class="favorite" on:click={() => runtime.toggleFavorite(node.id)} aria-label={node.favorite ? '取消收藏' : '收藏'}><Star size={14} fill={node.favorite ? 'currentColor' : 'none'} /></button></td>{/if}
          <td><strong>{node.name}</strong></td><td class="muted">{node.subtitle}</td><td class="address mono">{node.address}</td><td class="latency number {latencyTone(node.latencyMs)}">{Number.isFinite(node.latencyMs) ? `${node.latencyMs} ms` : '未测试'}</td>
          <td class="action">{#if node.id === currentNodeId && currentNodeId}<span class="current-label">当前</span>{:else}<button class="row-button" on:click={() => runtime.switchNode(node.id)}>连接</button>{/if}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  th:nth-child(1), td:nth-child(1) { width: 18%; }
  .address { width: 34%; color: #9fc9ef; }
  .latency { width: 14%; } .action { width: 82px; text-align: right; }
  tr.current { background: rgba(255,255,255,.025); box-shadow: inset 2px 0 var(--green); }
  .current-label { color: var(--text-2); font-size: 11px; }
  .good { color: #45d45b; } .warning { color: #e8a714; } .danger { color: #ff514b; } .muted { color: var(--text-3); }
  .fav { width: 38px !important; padding-right: 0; }
  .favorite { width: 24px; height: 24px; display: grid; place-items: center; border: 0; background: none; color: var(--text-3); padding: 0; cursor: pointer; }
  .favorite.active { color: #d9b14a; }
</style>
