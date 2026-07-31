<script>
  import { clearToken, changePassword, getStatus, getToken, login } from '../lib/api'
  import { t } from '../lib/i18n.js'
  import { isConnected } from '../lib/stores'

  export let notify
  export let authRequired = false
  export let onLoginSuccess = () => {}

  let password = ''
  let oldPassword = ''
  let newPassword = ''
  let status = null

  async function doLogin() {
    try {
      await login(password)
      password = ''
      notify('success', t('loginSuccess'), t('actionSuccess'))
      onLoginSuccess()
    } catch (error) {
      notify('error', t('loginFailed'), error.message)
    }
  }

  function logout() {
    clearToken()
    notify('info', t('logoutSuccess'), t('tokenNotSet'))
  }

  async function doChangePassword() {
    if (!oldPassword || !newPassword) return
    try {
      await changePassword(oldPassword, newPassword)
      oldPassword = ''
      newPassword = ''
      clearToken()
      notify('success', t('changePassword'), t('passwordChanged'))
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    } catch (error) {
      notify('error', t('actionFailed'), error.message)
    }
  }

  getStatus().then((data) => (status = data)).catch(() => {})
</script>

<section class="page">
  <div class="header">
    <div>
      <h1>{t('settingsTitle')}</h1>
      <p>{t('settingsDesc')}</p>
    </div>
  </div>

  <div class="card">
    <h3>{t('settingsAuth')}</h3>
    <div class="auth-grid">
      <input bind:value={password} type="password" placeholder={t('settingsPassword')} />
      <button on:click={doLogin}>{t('login')}</button>
      <button on:click={logout}>{t('logout')}</button>
    </div>
    <p>{t('tokenStatus')}: <strong>{getToken() ? t('tokenPresent') : t('tokenNotSet')}</strong></p>
    {#if authRequired}
      <p class="warning">{t('tokenWarning')}</p>
    {/if}
  </div>

  <div class="card">
    <h3>{t('changePassword')}</h3>
    <div class="auth-grid wrap">
      <input bind:value={oldPassword} type="password" placeholder={t('currentPassword')} />
      <input bind:value={newPassword} type="password" placeholder={t('newPassword')} />
      <button on:click={doChangePassword}>{t('change')}</button>
    </div>
  </div>

  <div class="card">
    <h3>{t('settingsApi')}</h3>
    <p>{t('settingsBaseUrl')}: <code>/api/v1</code></p>
    <p>{t('settingsEvents')}: <strong>{$isConnected ? t('connected') : t('disconnected')}</strong></p>
  </div>

  <div class="card">
    <h3>{t('settingsAbout')}</h3>
    <p>{t('settingsProject')}</p>
    <p>{t('settingsVersion')}: <strong>{status?.version || '0.1.0'}</strong></p>
    <p>{t('settingsBuild')}</p>
  </div>
</section>

<style>
  .page { display: grid; gap: 1rem; }
  h1, h3 { margin: 0; }
  p { margin: 0.6rem 0 0; color: #8b949e; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 14px; padding: 1rem; }
  .auth-grid { display: flex; gap: 0.75rem; margin-top: 1rem; }
  .wrap { flex-wrap: wrap; }
  input, button {
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.65rem 0.8rem;
  }
  input { min-width: 260px; }
  code { font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; color: #c9d1d9; }
  .warning { color: #d29922; }
</style>
