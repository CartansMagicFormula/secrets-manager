// Secrets manager admin UI. Vanilla JS, no dependencies.
// Security: data is only ever inserted with textContent (never innerHTML);
// every state-changing request sends the CSRF header; the session is an
// HttpOnly cookie the script cannot read.
'use strict'

const $ = (sel) => document.querySelector(sel)
const views = ['init', 'masterkey', 'unseal', 'login', 'secrets', 'clients', 'audit']

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: 'same-origin' }
  if (method !== 'GET') opts.headers['X-Requested-With'] = 'secrets-manager'
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(path, opts)
  const data = res.status === 204 ? null : await res.json().catch(() => null)
  if (!res.ok) {
    const err = new Error((data && data.error) || 'Request failed')
    err.status = res.status
    throw err
  }
  return data
}

function toast(message, tone = 'info') {
  const el = $('#toast')
  el.textContent = message
  el.className = `toast ${tone}`
  clearTimeout(toast.timer)
  toast.timer = setTimeout(() => el.classList.add('hidden'), 4500)
}

function show(name) {
  for (const v of views) $(`#view-${v}`).classList.toggle('hidden', v !== name)
  const inside = ['secrets', 'clients', 'audit'].includes(name)
  $('#tabs').classList.toggle('hidden', !inside)
  $('#seal').classList.toggle('hidden', !inside)
  $('#logout').classList.toggle('hidden', !inside)
  for (const t of document.querySelectorAll('.tab')) t.classList.toggle('active', t.dataset.view === name)
}

function cell(text, cls) {
  const td = document.createElement('td')
  td.textContent = text ?? ''
  if (cls) td.className = cls
  return td
}

function button(label, cls, onClick) {
  const b = document.createElement('button')
  b.textContent = label
  b.className = `btn sm ${cls}`
  b.addEventListener('click', onClick)
  return b
}

const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : '—')

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text)
    toast('Copied', 'success')
  } catch {
    toast('Copy failed: select the text and copy it manually', 'error')
  }
}

// ------------------------------------------------------------ boot

async function boot() {
  const status = await api('GET', '/v1/sys/status')
  $('#state').textContent = !status.initialized ? 'not initialized' : status.sealed ? 'sealed' : 'unsealed'
  $('#state').className = `pill ${status.sealed ? 'warn' : 'ok'}`
  if (!status.initialized) return show('init')
  if (status.sealed) return show('unseal')
  try {
    await api('GET', '/v1/admin/session')
    return openView('secrets')
  } catch {
    return show('login')
  }
}

function openView(name) {
  show(name)
  if (name === 'secrets') loadSecrets()
  if (name === 'clients') loadClients()
  if (name === 'audit') loadAudit()
}

function form(sel) {
  return Object.fromEntries(new FormData($(sel)).entries())
}

function showMasterKey(key, then) {
  $('#masterkey-value').textContent = key
  show('masterkey')
  $('#masterkey-done').onclick = () => {
    $('#masterkey-value').textContent = ''
    then()
  }
}

$('#masterkey-copy').addEventListener('click', () => copy($('#masterkey-value').textContent))

$('#init-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  try {
    const res = await api('POST', '/v1/sys/init', form('#init-form'))
    $('#init-form').reset()
    showMasterKey(res.master_key, () => boot())
  } catch (err) {
    toast(err.message, 'error')
  }
})

$('#unseal-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  try {
    await api('POST', '/v1/sys/unseal', form('#unseal-form'))
    $('#unseal-form').reset()
    await boot()
  } catch (err) {
    $('#unseal-form').reset()
    toast(err.status === 429 ? 'Too many attempts, wait a minute' : 'Unseal failed', 'error')
  }
})

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  try {
    await api('POST', '/v1/admin/login', form('#login-form'))
    $('#login-form').reset()
    await boot()
  } catch (err) {
    toast(err.status === 429 ? 'Too many attempts, wait a minute' : 'Invalid username or password', 'error')
  }
})

$('#logout').addEventListener('click', async () => {
  await api('POST', '/v1/admin/logout').catch(() => {})
  await boot()
})

$('#seal').addEventListener('click', async () => {
  if (!confirm('Seal the vault? Clients cannot read secrets until it is unsealed with the master key.')) return
  await api('POST', '/v1/sys/seal').catch((err) => toast(err.message, 'error'))
  await boot()
})

for (const t of document.querySelectorAll('.tab')) t.addEventListener('click', () => openView(t.dataset.view))

// ------------------------------------------------------------ secrets

$('#new-secret').addEventListener('click', () => $('#secret-form').classList.remove('hidden'))
$('#secret-cancel').addEventListener('click', () => {
  $('#secret-form').reset()
  $('#secret-form').classList.add('hidden')
  kindChanged()
})

function kindChanged() {
  const generated = $('#secret-form').kind.value === 'generated'
  for (const el of document.querySelectorAll('.static-only')) el.classList.toggle('hidden', generated)
  for (const el of document.querySelectorAll('.generated-only')) el.classList.toggle('hidden', !generated)
}
$('#secret-form').kind.addEventListener('change', kindChanged)

$('#secret-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  const f = form('#secret-form')
  const body = { kind: f.kind, note: f.note }
  if (f.kind === 'static') body.value = f.value
  else Object.assign(body, { alphabet: f.alphabet, length: Number(f.length) })
  try {
    await api('PUT', `/v1/admin/secrets/${f.path}`, body)
    $('#secret-form').reset()
    $('#secret-form').classList.add('hidden')
    kindChanged()
    toast('Saved', 'success')
    loadSecrets()
  } catch (err) {
    toast(err.message, 'error')
  }
})

async function loadSecrets() {
  const body = $('#secrets-body')
  body.replaceChildren()
  let list = []
  try {
    list = await api('GET', '/v1/admin/secrets')
  } catch (err) {
    if (err.status === 401) return show('login')
    return toast(err.message, 'error')
  }
  if (list.length === 0) {
    const tr = document.createElement('tr')
    tr.append(cell('No secrets yet.', 'muted'))
    body.append(tr)
  }
  for (const s of list) {
    const tr = document.createElement('tr')
    const actions = document.createElement('td')
    actions.className = 'actions'
    actions.append(
      button('Reveal', 'ghost', () => reveal(s.path)),
      ...(s.kind === 'generated' ? [button('Rotate', 'ghost', () => rotate(s.path))] : []),
      button('Delete', 'ghost danger-text', () => removeSecret(s.path)),
    )
    tr.append(
      cell(s.path, 'mono'),
      cell(s.kind === 'generated' ? `generated (${s.alphabet}, ${s.length})` : 'static'),
      cell(`v${s.current_version}`),
      cell(`${fmt(s.updated_at)} · ${s.updated_by}`, 'muted'),
      cell(s.readers.join(', ') || '—'),
      actions,
    )
    body.append(tr)
  }
}

async function reveal(path) {
  if (!confirm(`Reveal the value of ${path}? This is recorded in the audit log.`)) return
  try {
    const res = await api('POST', `/v1/admin/reveal/${path}`)
    // Shown in a prompt so it is not left in the page
    window.prompt(`${path} (v${res.version}) — copy, then close`, res.value)
  } catch (err) {
    toast(err.message, 'error')
  }
}

async function rotate(path) {
  if (!confirm(`Rotate ${path}? Clients get the new value; the previous one stays readable for the grace period.`)) return
  try {
    await api('POST', `/v1/admin/rotate/${path}`)
    toast('Rotated', 'success')
    loadSecrets()
  } catch (err) {
    toast(err.message, 'error')
  }
}

async function removeSecret(path) {
  if (!confirm(`Delete ${path} and all its versions? Clients reading it will fail.`)) return
  try {
    await api('DELETE', `/v1/admin/secrets/${path}`)
    loadSecrets()
  } catch (err) {
    toast(err.message, 'error')
  }
}

// ------------------------------------------------------------ clients

$('#new-client').addEventListener('click', () => $('#client-form').classList.remove('hidden'))
$('#client-cancel').addEventListener('click', () => {
  $('#client-form').reset()
  $('#client-form').classList.add('hidden')
})

$('#client-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  const f = form('#client-form')
  const policies = f.policies.split(/\s+/).filter(Boolean)
  try {
    const res = await api('POST', '/v1/admin/clients', { name: f.name, policies })
    $('#client-form').reset()
    $('#client-form').classList.add('hidden')
    $('#token-value').textContent = res.token
    $('#token-box').classList.remove('hidden')
    loadClients()
  } catch (err) {
    toast(err.message, 'error')
  }
})
$('#token-copy').addEventListener('click', () => copy($('#token-value').textContent))
$('#token-done').addEventListener('click', () => {
  $('#token-value').textContent = ''
  $('#token-box').classList.add('hidden')
})

async function loadClients() {
  const body = $('#clients-body')
  body.replaceChildren()
  let list = []
  try {
    list = await api('GET', '/v1/admin/clients')
  } catch (err) {
    if (err.status === 401) return show('login')
    return toast(err.message, 'error')
  }
  for (const c of list.sort((a, b) => a.name.localeCompare(b.name))) {
    const tr = document.createElement('tr')
    const actions = document.createElement('td')
    if (!c.revoked_at) actions.append(button('Revoke', 'ghost danger-text', () => revoke(c)))
    tr.append(
      cell(c.name, 'mono'),
      cell(c.policies.join(', '), 'mono'),
      cell(fmt(c.last_used_at), 'muted'),
      cell(c.revoked_at ? `revoked ${fmt(c.revoked_at)}` : 'active'),
      actions,
    )
    body.append(tr)
  }
}

async function revoke(c) {
  if (!confirm(`Revoke ${c.name}? Its token stops working immediately.`)) return
  await api('DELETE', `/v1/admin/clients/${c.id}`).catch((err) => toast(err.message, 'error'))
  loadClients()
}

$('#rotate-master').addEventListener('click', async () => {
  if (!confirm('Rotate the master key? The current key stops working; you must store the new one.')) return
  try {
    const res = await api('POST', '/v1/admin/master-key/rotate')
    showMasterKey(res.master_key, () => openView('clients'))
  } catch (err) {
    toast(err.message, 'error')
  }
})

// ------------------------------------------------------------ audit

async function loadAudit() {
  const body = $('#audit-body')
  body.replaceChildren()
  let list = []
  try {
    list = await api('GET', '/v1/admin/audit')
  } catch (err) {
    if (err.status === 401) return show('login')
    return toast(err.message, 'error')
  }
  for (const e of list) {
    const tr = document.createElement('tr')
    tr.append(
      cell(new Date(e.time).toISOString().replace('T', ' ').slice(0, 19), 'mono'),
      cell(e.actor),
      cell(e.action, 'mono'),
      cell(e.path, 'mono'),
      cell(e.version ? `v${e.version}` : ''),
      cell(e.ok ? 'ok' : `denied ${e.detail || ''}`, e.ok ? '' : 'danger-text'),
    )
    body.append(tr)
  }
}

$('#verify-audit').addEventListener('click', async () => {
  try {
    const res = await api('GET', '/v1/admin/audit/verify')
    $('#verify-result').textContent = res.ok
      ? `Chain intact: ${res.entries} entries. Head ${res.head.slice(0, 16)}…`
      : `CHAIN BROKEN: ${res.error}`
    $('#verify-result').className = res.ok ? 'ok-text' : 'danger-text'
  } catch (err) {
    toast(err.message, 'error')
  }
})

boot().catch(() => toast('Vault unreachable', 'error'))
