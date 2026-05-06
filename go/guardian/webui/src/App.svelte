<script>
  import { onDestroy, onMount } from 'svelte'
  import Dashboard from './routes/Dashboard.svelte'
  import Instances from './routes/Instances.svelte'
  import Configs from './routes/Configs.svelte'
  import Logs from './routes/Logs.svelte'
  import Binaries from './routes/Binaries.svelte'
  import Settings from './routes/Settings.svelte'
  import Toast from './lib/components/Toast.svelte'
  import { getToken, subscribeEvents } from './lib/api'
  import { getLang, setLang, t } from './lib/i18n.js'
  import { isConnected } from './lib/stores'

  const pages = [
    { id: 'dashboard', label: 'navDashboard', icon: 'home' },
    { id: 'instances', label: 'navInstances', icon: 'server' },
    { id: 'configs', label: 'navConfigs', icon: 'file' },
    { id: 'logs', label: 'navLogs', icon: 'terminal' },
    { id: 'binaries', label: 'navBinaries', icon: 'package' },
    { id: 'settings', label: 'navSettings', icon: 'gear' },
  ]

  let currentPage = 'dashboard'
  let toast = null
  let authRequired = !getToken()
  let closeEvents = null
  let lang = getLang()

  function navigate(page) {
    currentPage = page
  }

  function notify(type, title, message) {
    toast = { type, title, message }
    clearTimeout(notify.timer)
    notify.timer = setTimeout(() => (toast = null), 3200)
  }

  function setupEvents() {
    closeEvents?.()
    closeEvents = subscribeEvents(
      (event) => {
        if (event?.message) {
          notify('info', event.type || t('settingsEvents'), event.message)
        }
      },
      (state) => isConnected.set(state),
    )
  }

  function handleUnauthorized() {
    authRequired = true
    currentPage = 'settings'
    notify('error', t('authRequired'), t('authRequiredDesc'))
  }

  function handleLoginSuccess() {
    authRequired = false
    setupEvents()
  }

  function toggleLanguage() {
    setLang(lang === 'zh' ? 'en' : 'zh')
  }

  function handleLangChange() {
    lang = getLang()
  }

  function icon(name) {
    const icons = {
      home: 'M3 10.5 12 3l9 7.5V21h-6v-6H9v6H3z',
      server: 'M4 5h16v6H4zm0 8h16v6H4zm3-5h2m-2 8h2',
      file: 'M7 3h7l5 5v13H7zM14 3v5h5',
      terminal: 'M4 6h16v12H4zm3 3 3 3-3 3m5 0h5',
      package: 'M12 2l8 4v12l-8 4-8-4V6zm0 0v8m8-4-8 4-8-4',
      gear: 'M12 8.5A3.5 3.5 0 1 1 8.5 12 3.5 3.5 0 0 1 12 8.5zm8 3.5-1.8-.7a6.8 6.8 0 0 0-.5-1.3l.8-1.8-2-2-.1.1-1.7.7a6.8 6.8 0 0 0-1.3-.5L12 4l-1.4 1.9a6.8 6.8 0 0 0-1.3.5L7.6 5.7l-.1-.1-2 2 .8 1.8a6.8 6.8 0 0 0-.5 1.3L4 12l1.8.7a6.8 6.8 0 0 0 .5 1.3l-.8 1.8 2 2 .1-.1 1.7-.7a6.8 6.8 0 0 0 1.3.5L12 20l1.4-1.9a6.8 6.8 0 0 0 1.3-.5l1.7.7.1.1 2-2-.8-1.8a6.8 6.8 0 0 0 .5-1.3z',
    }
    return icons[name]
  }

  onMount(() => {
    window.addEventListener('auth:unauthorized', handleUnauthorized)
    window.addEventListener('lang:changed', handleLangChange)
    if (getToken()) {
      authRequired = false
      setupEvents()
    }
  })

  onDestroy(() => {
    closeEvents?.()
    window.removeEventListener('auth:unauthorized', handleUnauthorized)
    window.removeEventListener('lang:changed', handleLangChange)
    clearTimeout(notify.timer)
  })
</script>

<div class="app-shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="logo">G</div>
      <div>
        <strong>{t('brand')}</strong>
        <small>{t('brandDesc')}</small>
      </div>
    </div>

    <nav>
      {#each pages as page}
        <button class:active={currentPage === page.id} on:click={() => navigate(page.id)}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d={icon(page.icon)}></path>
          </svg>
          <span>{t(page.label)}</span>
        </button>
      {/each}
    </nav>
  </aside>

  <main class="main">
    <header class="topbar">
      <div>
        <h1>{t('appTitle')}</h1>
        <p>{t('appDesc')}</p>
      </div>
      <div class="topbar-actions">
        <button class="lang-toggle" on:click={toggleLanguage}>EN/中文</button>
        <div class="connection {$isConnected ? 'connected' : 'disconnected'}">
          <i></i>
          {$isConnected ? t('connected') : t('disconnected')}
        </div>
      </div>
    </header>

    {#if authRequired && currentPage !== 'settings'}
      <section class="login-guard panel">
        <h2>{t('authRequired')}</h2>
        <p>{t('authRequiredDesc')}</p>
        <button on:click={() => navigate('settings')}>{t('openSettings')}</button>
      </section>
    {:else}
      <section class="content">
        {#if currentPage === 'dashboard'}
          <Dashboard {navigate} {notify} />
        {:else if currentPage === 'instances'}
          <Instances {notify} />
        {:else if currentPage === 'configs'}
          <Configs {notify} />
        {:else if currentPage === 'logs'}
          <Logs {notify} />
        {:else if currentPage === 'binaries'}
          <Binaries {notify} />
        {:else if currentPage === 'settings'}
          <Settings {notify} {authRequired} {handleLoginSuccess} onLoginSuccess={handleLoginSuccess} />
        {/if}
      </section>
    {/if}
  </main>

  <Toast {toast} />
</div>

<style>
  :global(body) {
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    color: #c9d1d9;
    background: #0d1117;
  }

  .app-shell {
    min-height: 100vh;
    display: grid;
    grid-template-columns: 250px 1fr;
  }

  .sidebar {
    background: #161b22;
    border-right: 1px solid #30363d;
    padding: 1.25rem 1rem;
    display: grid;
    align-content: start;
    gap: 1.5rem;
  }

  .brand {
    display: flex;
    gap: 0.85rem;
    align-items: center;
  }

  .logo {
    width: 42px;
    height: 42px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, #58a6ff, #0d419d);
    color: white;
    font-weight: 700;
  }

  .brand strong,
  .topbar h1 {
    display: block;
  }

  .brand small,
  .topbar p {
    color: #8b949e;
  }

  nav {
    display: grid;
    gap: 0.45rem;
  }

  nav button,
  .login-guard button {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
    padding: 0.8rem 0.9rem;
    border: 1px solid transparent;
    background: transparent;
    color: #c9d1d9;
    border-radius: 10px;
    cursor: pointer;
    text-align: left;
  }

  nav button:hover {
    background: rgba(88, 166, 255, 0.08);
  }

  nav button.active {
    background: rgba(88, 166, 255, 0.14);
    border-color: rgba(88, 166, 255, 0.35);
    color: #58a6ff;
  }

  svg {
    width: 18px;
    height: 18px;
    flex: none;
  }

  .main {
    display: grid;
    grid-template-rows: auto 1fr;
    min-width: 0;
  }

  .topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid #30363d;
    background: rgba(13, 17, 23, 0.96);
    position: sticky;
    top: 0;
    z-index: 10;
  }

  .topbar-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .topbar h1 {
    margin: 0;
    font-size: 1.45rem;
  }

  .topbar p {
    margin: 0.35rem 0 0;
  }

  .connection {
    display: inline-flex;
    align-items: center;
    gap: 0.55rem;
    padding: 0.5rem 0.8rem;
    border-radius: 999px;
    border: 1px solid #30363d;
    background: #161b22;
    font-size: 0.9rem;
  }

  .lang-toggle {
    border: 1px solid #30363d;
    border-radius: 999px;
    background: #21262d;
    color: #c9d1d9;
    padding: 0.5rem 0.9rem;
    cursor: pointer;
  }

  .connection i {
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 50%;
    background: #f85149;
  }

  .connection.connected i {
    background: #3fb950;
  }

  .content {
    padding: 1.5rem;
    min-width: 0;
  }

  .panel,
  .login-guard {
    margin: 1.5rem;
    padding: 1.25rem;
    border-radius: 14px;
    border: 1px solid #30363d;
    background: #161b22;
  }

  .login-guard h2 {
    margin: 0;
  }

  .login-guard p {
    color: #8b949e;
  }

  .login-guard button {
    width: fit-content;
    background: #21262d;
    border-color: #30363d;
  }

  @media (max-width: 960px) {
    .app-shell {
      grid-template-columns: 1fr;
    }

    .sidebar {
      border-right: 0;
      border-bottom: 1px solid #30363d;
    }
  }
</style>
