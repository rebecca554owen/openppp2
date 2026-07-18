<script>
  import { Search } from 'lucide-svelte'
  import NodeTable from '../lib/components/NodeTable.svelte'
  export let state
  export let runtime
  let query = ''
  let sort = 'latency'
  $: filtered = state.subscription.nodes
    .filter((node) => `${node.name} ${node.subtitle} ${node.address}`.toLowerCase().includes(query.trim().toLowerCase()))
    .toSorted((a, b) => sort === 'name' ? a.name.localeCompare(b.name, 'zh-CN') : (a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity))
</script>

<div class="page">
  <section class="panel">
    <div class="panel-head"><h1 class="panel-title">节点</h1><span class="subtle">{filtered.length} 个节点</span></div>
    <div class="toolbar-area">
      <label class="search"><Search size={14} /><input bind:value={query} placeholder="搜索名称、副标题或地址" aria-label="搜索节点" /></label>
      <select class="select-input" bind:value={sort} aria-label="节点排序"><option value="latency">按延迟</option><option value="name">按名称</option></select>
    </div>
    <NodeTable nodes={filtered} currentNodeId={state.connection.currentNodeId} {runtime} showFavorite />
  </section>
</div>

<style>
  .toolbar-area { padding: 11px 16px; display: flex; gap: 8px; border-bottom: 1px solid var(--border); }
  .search { min-width: 220px; max-width: 420px; flex: 1; height: 34px; display: flex; align-items: center; gap: 8px; border: 1px solid var(--border-strong); border-radius: 7px; padding: 0 10px; background: #0d1014; color: var(--text-3); }
  .search input { min-width: 0; flex: 1; border: 0; outline: 0; background: transparent; color: var(--text); }
  .select-input { width: 112px; padding-top: 0; padding-bottom: 0; }
</style>
