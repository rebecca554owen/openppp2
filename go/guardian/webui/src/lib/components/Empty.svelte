<script>
  import { t } from '../i18n.js'
  export let message = t('noData')
</script>

<div class="empty">
  <p>{message}</p>
</div>

<style>
  .empty {
    display: grid;
    place-items: center;
    min-height: 160px;
    border: 1px dashed #30363d;
    border-radius: 14px;
    background: rgba(22, 27, 34, 0.45);
    color: #8b949e;
  }

  p {
    margin: 0;
  }
</style>
