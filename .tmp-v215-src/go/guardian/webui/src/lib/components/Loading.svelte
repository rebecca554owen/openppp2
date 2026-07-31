<script>
  import { t } from '../i18n.js'
</script>

<div class="loading">
  <div class="spinner"></div>
  <span>{t('loading')}</span>
</div>

<style>
  .loading {
    display: grid;
    place-items: center;
    min-height: 120px;
    gap: 0.75rem;
    color: #8b949e;
  }

  .spinner {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    border: 3px solid #30363d;
    border-top-color: #58a6ff;
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
