<script>
  import { onMount } from 'svelte'
  import { selectedInstance } from '../lib/stores'
  import { getInstance, getInstanceLogs, startInstance, stopInstance, restartInstance } from '../lib/api'
  import { t } from '../lib/i18n.js'
  import StatusBadge from '../lib/components/StatusBadge.svelte'
  import Loading from '../lib/components/Loading.svelte'
  import Empty from '../lib/components/Empty.svelte'

  export let notify

  let instance = null
  let logs = []
  let loading = true
  let stream = 'all'

  $: currentName = $selectedInstance

  function formatDate(value) {
    return value ? new Date(value).toLocaleString() : '—'
  }

  async function load() {
    if (!currentName) {
      loading = false
      return
    }

    loading = true
    try {
      instance = await getInstance(currentName)
      logs = await getInstanceLogs(currentName, { stream, n: 50 }) || []
    } catch (error) {
      notify('error', t('failedToLoadInstance'), error.message)
    } finally {
      loading = false
    }
  }

  async function act(action) {
    try {
      if (action === 'start') await startInstance(currentName)
      if (action === 'stop') await stopInstance(currentName)
      if (action === 'restart') await restartInstance(currentName)
      notify('success', t('instanceUpdated'), `${currentName} ${t(`instance${action[0].toUpperCase()}${action.slice(1)}`)}`)
      await load()
    } catch (error) {
      notify('error', t('instanceActionFailed'), error.message)
    }
  }

  $: if (currentName) {
    load()
  }

  onMount(() => {
    if (currentName) load()
  })
</script>

<section class="page">
  <div class="header">
    <div>
      <h1>{t('navInstances')}</h1>
      <p>{t('detailedProcessState')}</p>
    </div>
    {#if instance}
      <div class="actions">
        <button on:click={() => act('start')}>{t('instanceStart')}</button>
        <button on:click={() => act('stop')}>{t('instanceStop')}</button>
        <button class="accent" on:click={() => act('restart')}>{t('instanceRestart')}</button>
      </div>
    {/if}
  </div>

  {#if !currentName}
    <Empty message={t('selectInstanceHint')} />
  {:else if loading}
    <Loading />
  {:else if instance}
    <div class="top card">
      <div>
        <h2>{instance.name}</h2>
        <p>{instance.binary}</p>
      </div>
      <StatusBadge running={instance.running} crashed={!instance.running && !!instance.lastExit && !instance.lastExit.success} />
    </div>

    <div class="grid">
      <div class="card">
        <h3>{t('processInfo')}</h3>
        <table>
          <tbody>
            <tr><th>{t('instancePID')}</th><td>{instance.pid || '—'}</td></tr>
            <tr><th>{t('startedAt')}</th><td>{formatDate(instance.startedAt)}</td></tr>
            <tr><th>{t('stoppedAt')}</th><td>{formatDate(instance.stoppedAt)}</td></tr>
            <tr><th>{t('instanceBinary')}</th><td>{instance.binary}</td></tr>
            <tr><th>{t('instanceWorkDir')}</th><td>{instance.workDir}</td></tr>
            <tr><th>{t('instanceConfig')}</th><td>{instance.configPath}</td></tr>
            <tr><th>{t('instanceArgs')}</th><td>{instance.args?.join(' ') || '—'}</td></tr>
            <tr><th>{t('instanceAutoRestart')}</th><td>{instance.autoRestart ? t('enabled') : t('disabled')}</td></tr>
            <tr><th>{t('instanceRestartCount')}</th><td>{instance.restartCount ?? 0}</td></tr>
          </tbody>
        </table>
      </div>

      <div class="card">
        <h3>{t('lastExitTitle')}</h3>
        <table>
          <tbody>
            <tr><th>{t('code')}</th><td>{instance.lastExit?.code ?? '—'}</td></tr>
            <tr><th>{t('success')}</th><td>{instance.lastExit?.success ? t('yes') : t('no')}</td></tr>
            <tr><th>{t('error')}</th><td>{instance.lastExit?.error || '—'}</td></tr>
            <tr><th>{t('at')}</th><td>{formatDate(instance.lastExit?.at)}</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    {#if instance.runtimeStats && Object.keys(instance.runtimeStats).length > 0}
      <div class="card stats-card">
        <h3>{t('runtimeStats')}</h3>
        <div class="stats-grid">
          {#each ['application', 'max concurrent', 'process', 'triplet', 'cwd', 'template', 'managed server', 'vpn server', 'http proxy', 'socks proxy', 'p/a controller', 'public ip', 'interface ip', 'hosting environment', 'name', 'index', 'interface', 'aggligator', 'proxy interlayer', 'tcp/ip cc', 'block quic', 'mux state', 'link state', 'mode', 'config', 'duration', 'sessions', 'tx', 'rx', 'in', 'out'] as key}
            {#if instance.runtimeStats[key]}
              <div class="stat-item">
                <span class="stat-label">{key}</span>
                <span class="stat-value">{instance.runtimeStats[key]}</span>
              </div>
            {/if}
          {/each}
          {#each Object.entries(instance.runtimeStats) as [key, value]}
            {#if !['application', 'max concurrent', 'process', 'triplet', 'cwd', 'template', 'managed server', 'vpn server', 'http proxy', 'socks proxy', 'p/a controller', 'public ip', 'interface ip', 'hosting environment', 'name', 'index', 'interface', 'aggligator', 'proxy interlayer', 'tcp/ip cc', 'block quic', 'mux state', 'link state', 'mode', 'config', 'duration', 'sessions', 'tx', 'rx', 'in', 'out'].includes(key)}
              <div class="stat-item">
                <span class="stat-label">{key}</span>
                <span class="stat-value">{value}</span>
              </div>
            {/if}
          {/each}
        </div>
      </div>
    {/if}

    <div class="card logs-card">
      <div class="logs-header">
        <h3>{t('recentLogs')}</h3>
        <select bind:value={stream} on:change={load}>
          <option value="all">{t('allStreams')}</option>
          <option value="stdout">{t('stdout')}</option>
          <option value="stderr">{t('stderr')}</option>
        </select>
      </div>

      <div class="logs">
        {#if logs.length === 0}
          <Empty message={t('noLogLinesReturned')} />
        {:else}
          {#each logs as log}
            <div class="line {log.stream}">
              <span>[{new Date(log.at).toLocaleTimeString()}]</span>
              <strong>{t(log.stream)}</strong>
              <code>{log.text}</code>
            </div>
          {/each}
        {/if}
      </div>
    </div>
  {/if}
</section>

<style>
  .page, .grid { display: grid; gap: 1rem; }
  .header, .top, .actions, .logs-header { display: flex; }
  .header, .top, .logs-header { justify-content: space-between; align-items: center; gap: 1rem; }
  .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  h1, h2, h3 { margin: 0; }
  p { margin: 0.35rem 0 0; color: #8b949e; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 14px; padding: 1rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.7rem 0; border-bottom: 1px solid #21262d; text-align: left; vertical-align: top; }
  th { width: 140px; color: #8b949e; font-weight: 500; }
  .logs { max-height: 420px; overflow: auto; display: grid; gap: 0.45rem; font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; }
  .line { display: grid; grid-template-columns: 100px 64px 1fr; gap: 0.75rem; font-size: 0.85rem; }
  .stdout strong { color: #58a6ff; }
  .stderr strong { color: #f85149; }
  code { white-space: pre-wrap; color: #c9d1d9; }
  button, select {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.65rem 0.9rem;
  }
  .actions { gap: 0.65rem; }
  .accent { background: #0d419d; border-color: #0d419d; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 0.8rem; }
  .stat-item { background: #0d1117; border: 1px solid #21262d; border-radius: 10px; padding: 0.65rem 0.85rem; }
  .stat-label { display: block; color: #8b949e; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; margin-bottom: 0.25rem; }
  .stat-value { display: block; color: #c9d1d9; font-size: 1rem; font-weight: 600; font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; }
  @media (max-width: 980px) { .grid { grid-template-columns: 1fr; } }
</style>
