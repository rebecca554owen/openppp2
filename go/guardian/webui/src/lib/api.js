const TOKEN_KEY = 'openppp2.guardian.token'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setToken(token) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token)
  }
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
}

function buildUrl(path) {
  return path.startsWith('/api/') ? path : `/api/v1${path}`
}

async function parseResponse(response) {
  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return response.json()
  }

  const text = await response.text()
  return text ? { message: text } : null
}

export async function request(method, path, body) {
  const headers = {}
  const token = getToken()

  if (token) {
    headers.Authorization = `Bearer ${token}`
  }

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }

  const response = await fetch(buildUrl(path), {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })

  const payload = await parseResponse(response)

  if (!response.ok) {
    if (response.status === 401) {
      clearToken()
      window.dispatchEvent(new CustomEvent('auth:unauthorized'))
    }

    const message = payload?.error || payload?.message || `${response.status} ${response.statusText}`
    throw new Error(message)
  }

  return payload
}

export async function login(password) {
  const data = await request('POST', '/auth/login', { password })
  if (data?.token) {
    setToken(data.token)
  }
  return data
}

export const changePassword = (oldPassword, newPassword) => request('PUT', '/auth/password', { oldPassword, newPassword })

export const getStatus = () => request('GET', '/status')
export const getInstances = () => request('GET', '/instances')
export const getInstance = (name) => request('GET', `/instances/${encodeURIComponent(name)}`)
export const createInstance = (cfg) => request('POST', '/instances', { ...cfg, tuiEnabled: cfg.tuiEnabled || false })
export const updateInstance = (name, cfg) => request('PUT', `/instances/${encodeURIComponent(name)}`, { ...cfg, tuiEnabled: cfg.tuiEnabled || false })
export const removeInstance = (name) => request('DELETE', `/instances/${encodeURIComponent(name)}`)
export const startInstance = (name) => request('POST', `/instances/${encodeURIComponent(name)}/start`)
export const stopInstance = (name) => request('POST', `/instances/${encodeURIComponent(name)}/stop`)
export const restartInstance = (name) => request('POST', `/instances/${encodeURIComponent(name)}/restart`)
export const saveGuardianConfig = (cfg) => request('PUT', '/guardian/config', cfg)

export function getInstanceLogs(name, opts = {}) {
  const params = new URLSearchParams()
  if (opts.stream && opts.stream !== 'all') {
    params.set('stream', opts.stream)
  }
  if (opts.n) {
    params.set('n', String(opts.n))
  }
  const suffix = params.toString() ? `?${params.toString()}` : ''
  return request('GET', `/instances/${encodeURIComponent(name)}/logs${suffix}`)
}

export const getProfiles = () => request('GET', '/profiles')
export const getProfile = (name) => request('GET', `/profiles/${encodeURIComponent(name)}`)
export const saveProfile = (name, content) => request('PUT', `/profiles/${encodeURIComponent(name)}`, { content })
export const deleteProfile = (name) => request('DELETE', `/profiles/${encodeURIComponent(name)}`)
export const validateProfile = (content) => request('POST', `/profiles/${encodeURIComponent('_validate')}/validate`, { content })
export const getProfileBackups = (name) => request('GET', `/profiles/${encodeURIComponent(name)}/backups`)
export const restoreProfile = (name, backupId) => request('POST', `/profiles/${encodeURIComponent(name)}/restore/${encodeURIComponent(backupId)}`)
export const getBinaries = () => request('GET', '/binaries')
export const discoverBinaries = (dir) => request('GET', `/binaries/discover?dir=${encodeURIComponent(dir)}`)
export const registerBinary = (path) => request('POST', '/binaries', { path })
export const removeBinary = (id) => request('DELETE', `/binaries/${encodeURIComponent(id)}`)

function createSseUrl(path) {
  const url = new URL(buildUrl(path), window.location.origin)
  const token = getToken()
  if (token) {
    url.searchParams.set('token', token)
  }
  return url.toString()
}

function subscribe(path, onMessage, onStateChange) {
  const source = new EventSource(createSseUrl(path))

  source.onopen = () => onStateChange?.(true)
  source.onerror = () => onStateChange?.(false)
  source.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data))
    } catch {
      onMessage(event.data)
    }
  }

  return () => source.close()
}

export function subscribeLogs(name, onLog, onStateChange) {
  return subscribe(`/sse/logs/${encodeURIComponent(name)}`, onLog, onStateChange)
}

export function subscribeEvents(onEvent, onStateChange) {
  return subscribe('/sse/events', onEvent, onStateChange)
}
