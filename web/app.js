// Secrets manager admin UI. Vanilla JS, no dependencies.
// Security: data is only ever inserted with textContent (never innerHTML);
// every state-changing request sends the CSRF header; the session is an
// HttpOnly cookie the script cannot read.
'use strict'

const $ = (sel) => document.querySelector(sel)
const views = ['init', 'masterkey', 'unseal', 'login', 'secrets', 'clients', 'certificates', 'audit']

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
  const inside = ['secrets', 'clients', 'certificates', 'audit'].includes(name)
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
  $('#environment').textContent = status.environment
  $('#environment').className = `pill ${status.environment === 'production' ? 'warn' : ''}`
  document.title = `Secrets manager · ${status.environment}`
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
  if (name === 'certificates') loadCertificates()
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
  const pkiNames = f.pki_names.split(/\s+/).filter(Boolean)
  try {
    const res = await api('POST', '/v1/admin/clients', { name: f.name, policies, pki_names: pkiNames })
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
    actions.className = 'actions'
    if (!c.revoked_at) {
      actions.append(button('Enroll', 'ghost', () => enrollClient(c)), button('Revoke', 'ghost danger-text', () => revoke(c)))
    }
    tr.append(
      cell(c.name, 'mono'),
      cell(c.policies.join(', ') || '—', 'mono'),
      cell(c.pki_names.join(', ') || '—', 'mono'),
      cell(fmt(c.last_used_at), 'muted'),
      cell(c.revoked_at ? `revoked ${fmt(c.revoked_at)}` : 'active'),
      actions,
    )
    body.append(tr)
  }
  loadSessions()
}

async function revoke(c) {
  if (!confirm(`Revoke ${c.name}? Its start token and all its sessions stop working immediately.`)) return
  await api('DELETE', `/v1/admin/clients/${c.id}`).catch((err) => toast(err.message, 'error'))
  loadClients()
}

async function enrollClient(c) {
  const msg = `Create a one-time enrollment code for ${c.name}? Using it gives the service server a new ` +
    'start token; the current one keeps working for the grace period.'
  if (!confirm(msg)) return
  try {
    const res = await api('POST', `/v1/admin/clients/${c.id}/enroll`)
    $('#enroll-client').textContent = c.name
    $('#enroll-expires').textContent = fmt(res.expires_at)
    // Normally fleet.sh enrolls all clients itself; this is the manual equivalent
    $('#enroll-command').textContent =
      `docker run --rm -i --user 0:0 --cap-drop ALL --cap-add CHOWN --network vault-<stack> ` +
      `-v fleet-ca:/ca:ro -v vault-token-${c.name}:/tokens ` +
      `-e SM_URL=https://secrets-manager:8443 -e SM_CA_FILE=/ca/fleet-ca.crt ` +
      `--entrypoint /sm-agent secrets-manager:latest enroll -out /tokens/token -owner <service uid>:<gid>`
    $('#enroll-code').textContent = res.code
    $('#enroll-box').classList.remove('hidden')
  } catch (err) {
    toast(err.message, 'error')
  }
}
$('#enroll-copy').addEventListener('click', () => copy($('#enroll-code').textContent))
$('#enroll-done').addEventListener('click', () => {
  $('#enroll-code').textContent = ''
  $('#enroll-box').classList.add('hidden')
})

$('#apply-list').addEventListener('click', () => $('#apply-form').classList.remove('hidden'))
$('#apply-cancel').addEventListener('click', () => {
  $('#apply-form').reset()
  $('#apply-form').classList.add('hidden')
})
$('#apply-form').addEventListener('submit', async (e) => {
  e.preventDefault()
  let list
  try {
    list = JSON.parse(form('#apply-form').list)
  } catch {
    return toast('Not valid JSON', 'error')
  }
  try {
    const r = await api('POST', '/v1/admin/apply', list)
    const box = $('#apply-report')
    box.replaceChildren()
    const lines = [
      ['Created clients (enroll them next)', r.created_clients],
      ['Updated clients', r.updated_clients],
      ['Created generated secrets', r.created_secrets],
      ['Static secrets still to enter (Secrets tab)', r.missing_static],
      ['Clients in the vault but not in the list (not deleted)', r.clients_not_in_list],
    ]
    for (const [label, items] of lines) {
      const p = document.createElement('p')
      p.textContent = `${label}: ${items.length ? items.join(', ') : '—'}`
      box.append(p)
    }
    const p = document.createElement('p')
    p.className = 'muted'
    p.textContent = `Unchanged clients: ${r.unchanged_clients}`
    box.append(p)
    box.classList.remove('hidden')
    $('#apply-form').classList.add('hidden')
    loadClients()
  } catch (err) {
    toast(err.message, 'error')
  }
})

async function loadSessions() {
  const body = $('#sessions-body')
  body.replaceChildren()
  const list = await api('GET', '/v1/admin/sessions').catch((err) => {
    toast(err.message, 'error')
    return []
  })
  if (list.length === 0) {
    const tr = document.createElement('tr')
    tr.append(cell('No active sessions.', 'muted'))
    body.append(tr)
  }
  for (const s of list) {
    const tr = document.createElement('tr')
    const actions = document.createElement('td')
    actions.append(button('End', 'ghost danger-text', () => endSession(s)))
    tr.append(
      cell(s.client, 'mono'),
      cell(s.instance, 'mono'),
      cell(fmt(s.issued_at), 'muted'),
      cell(fmt(s.expires_at), 'muted'),
      cell(fmt(s.max_until), 'muted'),
      actions,
    )
    body.append(tr)
  }
}

async function endSession(s) {
  if (!confirm(`End the session of ${s.client} (${s.instance})? It must log in again with its start token.`)) return
  await api('DELETE', `/v1/admin/sessions/${s.id}`).catch((err) => toast(err.message, 'error'))
  loadSessions()
}

// ------------------------------------------------------------ certificates

async function loadCertificates() {
  const body = $('#certificates-body')
  body.replaceChildren()
  let res
  try {
    res = await api('GET', '/v1/admin/certificates')
  } catch (err) {
    if (err.status === 401) return show('login')
    return toast(err.message, 'error')
  }
  $('#ca-value').textContent = res.ca
  if (res.certificates.length === 0) {
    const tr = document.createElement('tr')
    tr.append(cell('No certificates issued yet.', 'muted'))
    body.append(tr)
  }
  const now = Date.now()
  for (const c of res.certificates) {
    const tr = document.createElement('tr')
    const expired = new Date(c.not_after).getTime() < now
    tr.append(
      cell(new Date(c.issued_at).toISOString().replace('T', ' ').slice(0, 19), 'mono'),
      cell(c.client, 'mono'),
      cell(c.usage),
      cell(c.names.join(', '), 'mono'),
      cell(expired ? `expired ${fmt(c.not_after)}` : fmt(c.not_after), expired ? 'muted' : ''),
      cell(c.serial.slice(0, 16), 'mono muted'),
    )
    body.append(tr)
  }
}

$('#ca-copy').addEventListener('click', () => copy($('#ca-value').textContent))

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
