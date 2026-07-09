<script>
  export let toast = null
</script>

{#if toast}
  <div class="toast {toast.type || 'info'}">
    <strong>{toast.title || 'Notice'}</strong>
    <span>{toast.message}</span>
  </div>
{/if}

<style>
  .toast {
    position: fixed;
    right: 1.25rem;
    bottom: 1.25rem;
    z-index: 50;
    min-width: 280px;
    max-width: 420px;
    display: grid;
    gap: 0.3rem;
    padding: 0.95rem 1rem;
    border-radius: 12px;
    border: 1px solid #30363d;
    background: #161b22;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
  }

  strong {
    font-size: 0.92rem;
  }

  span {
    color: #c9d1d9;
    font-size: 0.88rem;
  }

  .success {
    border-color: rgba(63, 185, 80, 0.45);
  }

  .error {
    border-color: rgba(248, 81, 73, 0.45);
  }

  .info {
    border-color: rgba(88, 166, 255, 0.45);
  }
</style>
