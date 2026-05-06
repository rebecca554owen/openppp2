<script>
  import { onDestroy, onMount } from 'svelte'
  import { getInstanceLogs, getInstances, subscribeLogs } from '../lib/api'
  import { t } from '../lib/i18n.js'
  import { instances, isConnected, selectedInstance } from '../lib/stores'
  import Empty from '../lib/components/Empty.svelte'

  export let notify

  let stream = 'all'
  let search = ''
  let paused = false
  let logs = []
  let unsubscribe = null
  let loadingBacklog = false

  $: current = $selectedInstance || $instances[0]?.name || ''
  $: filtered = logs.filter((log) => {
    const streamMatch = stream === 'all' || log.stream === stream
    const textMatch = !search || `${log.stream} ${log.text}`.toLowerCase().includes(search.toLowerCase())
    return streamMatch && textMatch
  })

  async function loadInstances() {
    try {
      const items = await getInstances()
      instances.set(Array.isArray(items) ? items : [])
      if (!$selectedInstance && items[0]?.name) {
        selectedInstance.set(items[0].name)
      }
    } catch (error) {
      notify('error', t('failedToLoadInstances'), error.message)
    }
  }

  async function loadBacklog() {
    if (!current) return
    loadingBacklog = true
    try {
      const items = await getInstanceLogs(current, { n: 200, stream })
      logs = Array.isArray(items) ? items : []
    } catch (error) {
      notify('error', t('failedToLoadLogs'), error.message)
      logs = []
    } finally {
      loadingBacklog = false
    }
  }

  function connect() {
    unsubscribe?.()
    if (!current) return
    unsubscribe = subscribeLogs(
      current,
      (entry) => {
        if (paused) return
        logs = [...logs.slice(-499), entry]
      },
      (state) => isConnected.set(state),
    )
  }

  function clearLogs() {
    logs = []
  }

  $: if (current) {
    loadBacklog()
    connect()
  }

  $: if (current && stream) {
    loadBacklog()
  }

  onMount(loadInstances)
  onDestroy(() => unsubscribe?.())
</script>

<section class="page">
  <div class="header">
    <div>
      <h1>{t('logsTitle')}</h1>
      <p>{t('logsLiveDesc')}</p>
    </div>
    <div class="controls">
      <select bind:value={$selectedInstance}>
        {#each $instances as instance}
          <option value={instance.name}>{instance.name}</option>
        {/each}
      </select>
      <select bind:value={stream}>
        <option value="all">{t('all')}</option>
        <option value="stdout">{t('stdout')}</option>
        <option value="stderr">{t('stderr')}</option>
      </select>
      <input bind:value={search} placeholder={t('searchLogs')} />
      <button on:click={() => (paused = !paused)}>{paused ? t('resume') : t('pause')}</button>
      <button on:click={clearLogs}>{t('clear')}</button>
    </div>
  </div>

  <div class="card log-panel">
    {#if !current}
      <Empty message={t('noInstanceSelectedLogs')} />
    {:else if loadingBacklog}
      <Empty message={t('loadingLogs')} />
    {:else if filtered.length === 0}
      <Empty message={t('waitingForLogEvents')} />
    {:else}
      <div class="log-list">
        {#each filtered as log}
            <div class="line {log.stream}">
              <span>{new Date(log.at).toLocaleTimeString()}</span>
              <strong>{t(log.stream)}</strong>
              <code>{log.text}</code>
            </div>
          {/each}
      </div>
    {/if}
  </div>
</section>

<style>
  .page { display: grid; gap: 1rem; }
  .header, .controls { display: flex; gap: 0.75rem; }
  .header { justify-content: space-between; align-items: flex-start; }
  h1 { margin: 0; }
  p { margin: 0.35rem 0 0; color: #8b949e; }
  .controls { flex-wrap: wrap; align-items: center; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 14px; padding: 1rem; }
  .log-panel { min-height: 520px; }
  .log-list {
    display: grid;
    gap: 0.45rem;
    max-height: 72vh;
    overflow: auto;
    font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
  }
  .line { display: grid; grid-template-columns: 92px 64px 1fr; gap: 0.75rem; font-size: 0.85rem; }
  .stdout strong { color: #58a6ff; }
  .stderr strong { color: #f85149; }
  code { color: #c9d1d9; white-space: pre-wrap; }
  input, select, button {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.65rem 0.8rem;
  }
  input { min-width: 220px; }
</style>
