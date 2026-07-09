<script>
  import { t } from '../i18n.js'
  export let running = false
  export let crashed = false

  $: label = crashed ? t('crashed') : running ? t('running') : t('stopped')
</script>

<span class:running class:stopped={!running && !crashed} class:crashed>
  <i></i>
  {label}
</span>

<style>
  span {
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    padding: 0.28rem 0.7rem;
    border-radius: 999px;
    border: 1px solid #30363d;
    background: #161b22;
    font-size: 0.82rem;
    color: #c9d1d9;
  }

  i {
    width: 0.55rem;
    height: 0.55rem;
    border-radius: 50%;
    background: #8b949e;
    box-shadow: 0 0 10px rgba(139, 148, 158, 0.35);
  }

  .running i {
    background: #3fb950;
    box-shadow: 0 0 12px rgba(63, 185, 80, 0.45);
  }

  .crashed i {
    background: #f85149;
    box-shadow: 0 0 12px rgba(248, 81, 73, 0.45);
  }
</style>
