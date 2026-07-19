import test from 'node:test'
import assert from 'node:assert/strict'
import { createTauriRuntime } from '../src/lib/runtime/tauri.js'

function fakeBridge() {
  const calls = []
  let eventHandler
  const bootstrap = {
    subscription: {
      url: 'https://sub.test/token', name: 'Real nodes', updatedAt: '2026-07-19T12:00:00Z',
      lastSyncedAt: '2026-07-19T12:01:00Z', cached: false, cacheAgeMinutes: 0,
      nodes: [{ id: 'real-1', name: 'Real 1', subtitle: 'edge', address: '127.0.0.1:20000', latencyMs: null, favorite: false }],
    },
    config: '{"concurrent":1}',
    settings: { autostart: false, closeToTray: true, disconnectOnExit: true, language: '简体中文', appearance: '深色', pppPath: '' },
  }
  return {
    calls,
    bridge: {
      core: { invoke: async (command, args) => { calls.push([command, args]); if (command === 'client_bootstrap') return bootstrap; return null } },
      event: { listen: async (_name, handler) => { eventHandler = handler; return () => { eventHandler = null } } },
    },
    emit(payload) { eventHandler?.({ payload }) },
  }
}

test('tauri runtime bootstraps without demo data and cleans up listener', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  const snapshots = []
  const unsubscribe = runtime.subscribe((state) => snapshots.push(state))
  await runtime.ready
  assert.equal(runtime.kind, 'tauri')
  assert.equal(snapshots[0].subscription.nodes.length, 0)
  assert.equal(snapshots.at(-1).subscription.nodes[0].id, 'real-1')
  assert.equal(snapshots.at(-1).connection.status, 'disconnected')
  await unsubscribe()
  assert.equal(fake.calls[0][0], 'client_bootstrap')
})

test('tauri runtime invokes commands and derives connection state only from events', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  let state
  runtime.subscribe((next) => { state = next })
  await runtime.ready

  await runtime.connect('real-1')
  assert.equal(state.connection.status, 'connecting')
  assert.equal(fake.calls.at(-1)[0], 'client_connect')
  fake.emit({ type: 'telemetry', payload: { message: 'session established role=main', severity: 'success', signal: 'connected' } })
  assert.equal(state.connection.status, 'connected')
  assert.equal(state.events.at(-1).message, 'session established role=main')

  fake.emit({ type: 'exited', payload: { code: 7, success: false } })
  assert.equal(state.connection.status, 'error')
  assert.equal(state.connection.exitCode, 7)
})

test('tauri runtime maps stats and persists edits through explicit commands', async () => {
  const fake = fakeBridge()
  const runtime = createTauriRuntime(fake.bridge)
  let state
  runtime.subscribe((next) => { state = next })
  await runtime.ready
  fake.emit({ type: 'stats', payload: { rxRateMbps: 8, txRateMbps: 2, rxBytes: 100, txBytes: 50, qualityPercent: 99, qualityGrade: 'Good', activeLinks: 2, effectivePath: 'direct' } })
  assert.equal(state.connection.statsAvailable, true)
  assert.equal(state.stats.rxRateMbps, 8)

  await runtime.updateConfig('{"concurrent":2}')
  await runtime.updateSetting('pppPath', 'C:\\ppp.exe')
  await runtime.toggleFavorite('real-1')
  assert.deepEqual(fake.calls.slice(-3).map(([name]) => name), ['client_update_config', 'client_update_setting', 'client_toggle_favorite'])
})
