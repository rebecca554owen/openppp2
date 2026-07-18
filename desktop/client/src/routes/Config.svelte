<script>
  import { Check, RotateCcw, Save } from 'lucide-svelte'
  export let state
  export let runtime
  let draft = state.config
  let message = ''

  function validate() {
    try { JSON.parse(draft); message = 'JSON 格式有效' } catch (error) { message = error.message }
  }
  function save() {
    try { JSON.parse(draft); runtime.updateConfig(draft); message = '配置已保存' } catch (error) { message = error.message }
  }
  function reset() { draft = state.config; message = '已恢复到上次保存内容' }
</script>

<div class="page">
  <section class="panel">
    <div class="panel-head"><h1 class="panel-title">配置</h1><div class="toolbar"><button class="secondary-button action" on:click={validate}><Check size={14} />校验</button><button class="secondary-button action" on:click={reset}><RotateCcw size={14} />恢复</button><button class="primary-button action" on:click={save}><Save size={14} />保存</button></div></div>
    <div class="panel-body"><div class="field"><label for="raw-config">原始 JSON</label><textarea id="raw-config" class="text-area" bind:value={draft} spellcheck="false"></textarea></div>{#if message}<div class="message mono">{message}</div>{/if}</div>
  </section>
</div>

<style>
  .action { display: inline-flex; align-items: center; gap: 7px; }
  .message { margin-top: 10px; color: #91b4d5; font-size: 11px; }
  @media (max-width: 600px) { .panel-head { align-items: flex-start; flex-direction: column; padding-top: 10px; padding-bottom: 10px; } }
</style>
