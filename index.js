'use strict';

require('dotenv').config();
const { Bot, InlineKeyboard, Keyboard } = require('grammy');
const fs = require('fs');
const path = require('path');

const BOT_TOKEN = process.env.BOT_TOKEN;
const XUI_BASE_URL = process.env.XUI_BASE_URL; // e.g. https://xui.example.com
const XUI_USERNAME = process.env.XUI_USERNAME;
const XUI_PASSWORD = process.env.XUI_PASSWORD;
const PUBLIC_HOST = process.env.PUBLIC_HOST; // e.g. vpn.example.com (domain or IP presented to clients)
const STATIC_EMAIL_DOMAIN = 'oodana.my.id';
const ADMIN_TELEGRAM_IDS = (process.env.ADMIN_TELEGRAM_IDS || '')
  .split(',')
  .map((s) => Number(String(s).trim()))
  .filter((n) => Number.isFinite(n));
function isAdmin(userId) {
  return ADMIN_TELEGRAM_IDS.includes(Number(userId));
}

// Optional: allow certain non-admin users to add clients without cek saldo
const ALLOW_ADD_USER_IDS = (process.env.ALLOW_ADD_USER_IDS || '')
  .split(',')
  .map((s) => Number(String(s).trim()))
  .filter((n) => Number.isFinite(n));
function canBypassSaldo(userId) {
  // Hanya admin yang boleh bypass saldo (non-admin tetap dipotong saldonya)
  return isAdmin(userId);
}

// Simple saldo storage
const DATA_DIR = path.join(__dirname, 'data');
const BALANCES_FILE = path.join(DATA_DIR, 'balances.json');

function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(BALANCES_FILE)) fs.writeFileSync(BALANCES_FILE, JSON.stringify({}), 'utf8');
}

function readBalances() {
  try {
    ensureDataFile();
    const raw = fs.readFileSync(BALANCES_FILE, 'utf8');
    return JSON.parse(raw || '{}');
  } catch {
    return {};
  }
}

function writeBalances(obj) {
  try {
    ensureDataFile();
    fs.writeFileSync(BALANCES_FILE, JSON.stringify(obj, null, 2), 'utf8');
  } catch {
    // ignore
  }
}

function getBalance(userId) {
  const store = readBalances();
  const key = String(userId);
  return Number(store[key] || 0);
}

function addBalance(userId, amount) {
  const store = readBalances();
  const key = String(userId);
  const prev = Number(store[key] || 0);
  store[key] = prev + Number(amount || 0);
  writeBalances(store);
  return store[key];
}

function deductBalance(userId, amount) {
  const store = readBalances();
  const key = String(userId);
  const prev = Number(store[key] || 0);
  const amt = Number(amount || 0);
  if (prev < amt) return { ok: false, balance: prev };
  store[key] = prev - amt;
  writeBalances(store);
  return { ok: true, balance: store[key] };
}

function formatIDR(amount) {
  return new Intl.NumberFormat('id-ID').format(Number(amount || 0));
}

const PRICE_BY_DAYS = { 3: 3000, 7: 6000, 30: 10000 };
const PAYMENT_INFO = '\nDANA \n081253439968 \nan Ollifer M*** O***\n';

// Topup requests storage
const TOPUPS_FILE = path.join(DATA_DIR, 'topups.json');
const LOG_FILE = path.join(DATA_DIR, 'logs.jsonl');
const TOPUP_TTL_MS = 5 * 60 * 1000; // 5 minutes
const BUGS_FILE = path.join(DATA_DIR, 'bugs.json');
// (moved) LOG_FILE declared above

function readTopups() {
  try {
    ensureDataFile();
    if (!fs.existsSync(TOPUPS_FILE)) fs.writeFileSync(TOPUPS_FILE, JSON.stringify([]), 'utf8');
    const raw = fs.readFileSync(TOPUPS_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch {
    return [];
  }
}

function writeTopups(arr) {
  try {
    ensureDataFile();
    fs.writeFileSync(TOPUPS_FILE, JSON.stringify(arr, null, 2), 'utf8');
  } catch {
    // ignore
  }
}

function createTopupRequest(userId, amount, uniqueCode) {
  const list = readTopups();
  const id = `${Date.now()}-${userId}`;
  const req = { id, userId: Number(userId), amount: Number(amount), uniqueCode: Number(uniqueCode || 0), status: 'pending', createdAt: Date.now() };
  list.unshift(req);
  writeTopups(list);
  return req;
}

function updateTopupStatus(id, status) {
  const list = readTopups();
  const idx = list.findIndex((t) => t.id === id);
  if (idx === -1) return null;
  list[idx].status = status;
  list[idx].updatedAt = Date.now();
  writeTopups(list);
  return list[idx];
}

function getPendingTopups(limit = 20) {
  return readTopups().filter((t) => t.status === 'pending').slice(0, limit);
}

function addTopupAdminNotif(topupId, chatId, messageId) {
  const list = readTopups();
  const idx = list.findIndex((t) => t.id === topupId);
  if (idx === -1) return;
  const cur = list[idx];
  cur.notifs = Array.isArray(cur.notifs) ? cur.notifs : [];
  cur.notifs.push({ chatId, messageId });
  writeTopups(list);
}

function popTopupAdminNotifs(topupId) {
  const list = readTopups();
  const idx = list.findIndex((t) => t.id === topupId);
  if (idx === -1) return [];
  const cur = list[idx];
  const notifs = Array.isArray(cur.notifs) ? cur.notifs : [];
  cur.notifs = [];
  writeTopups(list);
  return notifs;
}

// Activity logs (JSONL)
function ensureLogFile() {
  ensureDataFile();
  if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, '', 'utf8');
}

function logEvent(event) {
  try {
    ensureLogFile();
    const entry = {
      time: Date.now(),
      ...event
    };
    // Memastikan semua aktivitas client_created menyimpan creatorId
    if (event.type === 'client_created' && event.userId) {
      entry.creatorId = event.userId;
    }
    fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n', 'utf8');
  } catch {}
}

function readLogs(limit = 20, userIdFilter) {
  try {
    ensureLogFile();
    const raw = fs.readFileSync(LOG_FILE, 'utf8');
    const lines = raw.split(/\n/).filter(Boolean);
    const result = [];
    for (let i = lines.length - 1; i >= 0 && result.length < limit; i--) {
      try {
        const obj = JSON.parse(lines[i]);
        if (userIdFilter && String(obj.userId) !== String(userIdFilter) && String(obj.actorId || '') !== String(userIdFilter)) continue;
        result.push(obj);
      } catch {}
    }
    return result;
  } catch {
    return [];
  }
}

function formatLog(entry) {
  const when = new Date(entry.time).toLocaleString();
  const who = entry.actorId ? `Admin ${entry.actorId}` : `User ${entry.userId}`;
  switch (entry.type) {
    case 'topup_request':
      return `[${when}] ${who} mengajukan topup: total Rp ${formatIDR(entry.total)} (kode ${entry.uniqueCode}, id ${entry.id})`;
    case 'topup_ref':
      return `[${when}] User ${entry.userId} mengirim referensi topup id ${entry.id}: ${entry.ref}`;
    case 'topup_approved':
      return `[${when}] Admin ${entry.actorId} APPROVE topup id ${entry.id} untuk user ${entry.targetUserId} (+Rp ${formatIDR(entry.amount)})`;
    case 'topup_rejected':
      return `[${when}] Admin ${entry.actorId} REJECT topup id ${entry.id} untuk user ${entry.targetUserId}`;
    case 'client_created':
      return `[${when}] User ${entry.userId} membuat client ${entry.protocol.toUpperCase()} (${entry.email}) inbound ${entry.inboundId} durasi ${entry.days || '-'} hari`;
    case 'client_deleted':
      return `[${when}] Admin ${entry.actorId} menghapus client (${entry.clientKey}) dari inbound ${entry.inboundId}`;
    case 'topup_admin_add':
      return `[${when}] Admin ${entry.actorId} menambah saldo user ${entry.targetUserId} Rp ${formatIDR(entry.amount)}`;
    default:
      return `[${when}] ${who} ${entry.type}`;
  }
}

// BUG host management
function readBugs() {
  try {
    ensureDataFile();
    if (!fs.existsSync(BUGS_FILE)) fs.writeFileSync(BUGS_FILE, JSON.stringify(['quiz.int.vidio.com'], null, 2), 'utf8');
    const raw = fs.readFileSync(BUGS_FILE, 'utf8');
    const arr = JSON.parse(raw || '[]');
    return Array.isArray(arr) ? arr.filter(Boolean) : [];
  } catch {
    return [];
  }
}

function addBugHost(host) {
  const arr = readBugs();
  if (!arr.includes(host)) arr.push(host);
  fs.writeFileSync(BUGS_FILE, JSON.stringify(arr, null, 2), 'utf8');
  return arr;
}

function removeBugHost(host) {
  const arr = readBugs().filter((h) => h !== host);
  fs.writeFileSync(BUGS_FILE, JSON.stringify(arr, null, 2), 'utf8');
  return arr;
}

if (!BOT_TOKEN || !XUI_BASE_URL || !XUI_USERNAME || !XUI_PASSWORD || !PUBLIC_HOST) {
  console.error('Missing required env vars. Please set BOT_TOKEN, XUI_BASE_URL, XUI_USERNAME, XUI_PASSWORD, PUBLIC_HOST');
  process.exit(1);
}

function normalizeBaseUrl(url) {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

class XuiClient {
  constructor(options) {
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.username = options.username;
    this.password = options.password;
    this.cookie = '';
  }

  async login() {
    const res = await fetch(this.baseUrl + '/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'accept': 'application/json, text/plain, */*'
      },
      body: JSON.stringify({ username: this.username, password: this.password })
    });

    if (!res.ok) {
      throw new Error('Login gagal ke 3x-ui');
    }

    const setCookieArray = (res.headers.getSetCookie && res.headers.getSetCookie()) || (res.headers.raw ? res.headers.raw()['set-cookie'] : undefined) || [];
    const setCookie = Array.isArray(setCookieArray) ? setCookieArray.join('\n') : res.headers.get('set-cookie');
    if (!setCookie) {
      throw new Error('Login berhasil tapi cookie tidak diterima');
    }
    // Extract only name=value parts for Cookie header
    const cookiePairs = (Array.isArray(setCookieArray) ? setCookieArray : setCookie.split(/,(?=[^;]+?=)/)).map((c) => String(c).split(';')[0].trim()).filter(Boolean);
    this.cookie = cookiePairs.join('; ');
  }

  async _fetchJson(path, options = {}) {
    const defaultHeaders = {
      'content-type': 'application/json',
      'accept': 'application/json, text/plain, */*',
      'x-requested-with': 'XMLHttpRequest',
      ...(this.cookie ? { Cookie: this.cookie } : {})
    };
    const mergedHeaders = { ...defaultHeaders, ...(options.headers || {}) };
    const { headers: _ignored, ...rest } = options;
    const res = await fetch(this.baseUrl + path, {
      headers: mergedHeaders,
      redirect: 'manual',
      ...rest
    });
    if (!res.ok && res.status !== 204) {
      const text = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}: ${text || 'No body'}`);
    }
    const contentType = res.headers.get('content-type') || '';
    if (res.status === 204) return {};
    const text = await res.text().catch(() => '');
    if (!text) return {};
    if (contentType.includes('application/json')) {
      try {
        return JSON.parse(text);
      } catch {
        // fallthrough to raw
      }
    }
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text, status: res.status, contentType };
    }
  }

  async listInbounds() {
    // GET /panel/api/inbounds/list
    return this._fetchJson('/panel/api/inbounds/list');
  }

  async getInbound(id) {
    // GET /panel/api/inbounds/get/:id
    return this._fetchJson(`/panel/api/inbounds/get/${id}`);
  }

  async addClient(inboundId, client) {
    // POST /panel/api/inbounds/addClient
    try {
      const first = await this._fetchJson('/panel/api/inbounds/addClient', {
        method: 'POST',
        body: JSON.stringify({ id: inboundId, client })
      });
      if (first && first.success === false && typeof first.msg === 'string' && /unexpected end of json input/i.test(first.msg)) {
        // Fallback: some panels expect client as JSON string
        const second = await this._fetchJson('/panel/api/inbounds/addClient', {
          method: 'POST',
          body: JSON.stringify({ id: inboundId, client: JSON.stringify(client) })
        });
        if (second && second.success === false) {
          // Try urlencoded payload
          const form = new URLSearchParams();
          form.set('id', String(inboundId));
          form.set('client', JSON.stringify(client));
          const third = await this._fetchJson('/panel/api/inbounds/addClient', {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: form.toString()
          });
          return third;
        }
        return second;
      }
      // If response is not in the expected shape, still try urlencoded once
      if (!first || (first && first.success === undefined && first.raw)) {
        const form = new URLSearchParams();
        form.set('id', String(inboundId));
        form.set('client', JSON.stringify(client));
        const alt = await this._fetchJson('/panel/api/inbounds/addClient', {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: form.toString()
        });
        return alt;
      }
      return first;
    } catch (err) {
      const msg = String(err?.message || '');
      if (/unexpected end of json input/i.test(msg)) {
        // Fallback when server returned non-OK page with this message
        const second = await this._fetchJson('/panel/api/inbounds/addClient', {
          method: 'POST',
          body: JSON.stringify({ id: inboundId, client: JSON.stringify(client) })
        });
        if (second && second.success === false) {
          const form = new URLSearchParams();
          form.set('id', String(inboundId));
          form.set('client', JSON.stringify(client));
          const third = await this._fetchJson('/panel/api/inbounds/addClient', {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: form.toString()
          });
          return third;
        }
        return second;
      }
      throw err;
    }
  }

  async delClient(inboundId, clientId) {
    // POST /panel/api/inbounds/:id/delClient/:clientId
    try {
      const res = await this._fetchJson(`/panel/api/inbounds/${inboundId}/delClient/${encodeURIComponent(clientId)}`, {
        method: 'POST'
      });
      if (res && res.success === false) {
        // try urlencoded dummy body
        const form = new URLSearchParams();
        const alt = await this._fetchJson(`/panel/api/inbounds/${inboundId}/delClient/${encodeURIComponent(clientId)}`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: form.toString()
        });
        return alt;
      }
      return res;
    } catch (err) {
      // fallback attempt
      const form = new URLSearchParams();
      const alt = await this._fetchJson(`/panel/api/inbounds/${inboundId}/delClient/${encodeURIComponent(clientId)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: form.toString()
      });
      return alt;
    }
  }

  async updateInbound(inboundId, payload) {
    // POST /panel/api/inbounds/update/:id
    return this._fetchJson(`/panel/api/inbounds/update/${inboundId}`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  }

  async getClientTrafficsById(inboundId) {
    // GET /panel/api/inbounds/getClientTrafficsById/:id (API pada wiki)
    return this._fetchJson(`/panel/api/inbounds/getClientTrafficsById/${inboundId}`);
  }

  async updateClient(inboundId, clientIdOrKey, updates) {
    // Try updateClient endpoint first
    try {
      const bodyA = { id: inboundId, client: updates };
      const a = await this._fetchJson(`/panel/api/inbounds/updateClient/${encodeURIComponent(clientIdOrKey)}`, {
        method: 'POST',
        body: JSON.stringify(bodyA)
      });
      if (a && a.success !== false) return a;
      // Try with stringified client
      const b = await this._fetchJson(`/panel/api/inbounds/updateClient/${encodeURIComponent(clientIdOrKey)}`, {
        method: 'POST',
        body: JSON.stringify({ id: inboundId, client: JSON.stringify(updates) })
      });
      if (b && b.success !== false) return b;
    } catch {}
    // Fallback to full inbound update
    return { success: false };
  }
}

function ensureString(value, fallback = '') {
  if (typeof value === 'string') return value;
  if (value == null) return fallback;
  return String(value);
}

function toUsernameSlug(input) {
  const base = ensureString(input, '').trim().toLowerCase();
  return base.replace(/\s+/g, '_').replace(/[^a-z0-9._-]/g, '');
}

function makeEmailFromUserInput(input) {
  const raw = ensureString(input, '').trim();
  if (!raw) return '';
  const username = raw.includes('@') ? raw.split('@')[0] : raw;
  const safeUser = toUsernameSlug(username);
  if (!safeUser) return '';
  return `${safeUser}@${STATIC_EMAIL_DOMAIN}`;
}

function parseJsonIfString(maybeString, fallback = {}) {
  if (typeof maybeString === 'string') {
    try {
      return JSON.parse(maybeString);
    } catch {
      return fallback;
    }
  }
  return maybeString || fallback;
}

function deriveDomainHost(streamSettings, fallbackHost) {
  const wsHost = ensureString(streamSettings?.wsSettings?.headers?.Host, '');
  const tlsSni = ensureString(streamSettings?.tlsSettings?.serverName, '');
  return wsHost || tlsSni || fallbackHost;
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function chunkArray(array, size) {
  const out = [];
  for (let i = 0; i < array.length; i += size) out.push(array.slice(i, i + size));
  return out;
}

async function sendClientsList(ctx, { isAdminView }) {
  try {
    await xui.login();
    const list = await xui.listInbounds();
    const items = Array.isArray(list?.obj) ? list.obj : Array.isArray(list?.inbounds) ? list.inbounds : [];
    if (items.length === 0) {
      await ctx.reply('Tidak ada inbound.');
      return;
    }
    const entries = [];
    for (const inbound of items) {
      const settings = parseJsonIfString(inbound?.settings, {});
      const clients = Array.isArray(settings?.clients) ? settings.clients : [];
      if (clients.length === 0) continue;
      for (const c of clients) {
        if (!isAdminView) {
          // Filter berdasarkan domain dan pembuat client
          if (!String(c.email || '').endsWith(`@${STATIC_EMAIL_DOMAIN}`)) continue;
          // Hanya tampilkan client yang dibuat oleh user ini
          if (c.creatorId !== undefined && c.creatorId !== ctx.from?.id) continue;
        }
        const proto = inbound.protocol;
        const conf = buildConfigLink(proto, inbound, c);
        const header = `${proto.toUpperCase()} • ${inbound.remark || ''} • :${inbound.port}`;
        const email = c.email || '';
        const expiry = c.expiryTime ? new Date(Number(c.expiryTime)).toLocaleString() : '-';
        // Build action buttons for admin; for users, allow renew only on own domain
        const btns = new InlineKeyboard();
        const clientKey = c.id || c.password || c.email;
        btns.text('+3d (3000)', `renew_${inbound.id}_${encodeURIComponent(clientKey)}_3`) 
            .text('+7d (6000)', `renew_${inbound.id}_${encodeURIComponent(clientKey)}_7`) 
            .text('+30d (10000)', `renew_${inbound.id}_${encodeURIComponent(clientKey)}_30`);
        if (isAdminView) {
          btns.row().text('Aktif/Nonaktif', `toggle_${inbound.id}_${encodeURIComponent(clientKey)}`);
        }
        const content = `Inbound: ${header}\nEmail: ${email}\nExpiry: ${expiry}\nConfig:\n\n<code>${escapeHtml(conf)}</code>`;
        await ctx.reply(content, { parse_mode: 'HTML', reply_markup: btns });
      }
    }
    if (entries.length === 0) {
      await ctx.reply(isAdminView ? 'Tidak ada client.' : 'Tidak ada client Anda yang terdeteksi.');
      return;
    }
    const chunks = chunkArray(entries, 5);
    for (const group of chunks) {
      const text = group.join('\n\n');
      try {
        await ctx.reply(text.slice(0, 4000), { parse_mode: 'HTML' });
      } catch {
        await ctx.reply(group.map((t) => t.replace(/<[^>]+>/g, '')).join('\n\n'));
      }
    }
  } catch (err) {
    await ctx.reply(`Gagal memuat clients: ${err.message}`);
  }
}

function buildVmessLink({ host, port, clientId, remark, streamSettings }) {
  const network = ensureString(streamSettings?.network, 'tcp');
  const security = ensureString(streamSettings?.security, 'none');
  const wsSettings = streamSettings?.wsSettings || {};
  const wsPath = ensureString(wsSettings?.path, '/');
  const wsHost = ensureString(wsSettings?.headers?.Host, '');
  const tlsSettings = streamSettings?.tlsSettings || {};
  const sni = ensureString(tlsSettings?.serverName, host);
  const alpn = Array.isArray(tlsSettings?.alpn) ? tlsSettings.alpn.join(',') : ensureString(tlsSettings?.alpn || '');
  const fp = ensureString(tlsSettings?.fingerprint || '');
  const domainHost = deriveDomainHost(streamSettings, host);

  const vmessObj = {
    v: '2',
    ps: remark || 'vmess',
    add: host,
    port: String(port),
    id: clientId,
    aid: '0',
    scy: 'auto',
    net: network,
    type: 'none',
    host: domainHost,
    path: wsPath,
    tls: security === 'tls' ? 'tls' : '',
    sni: security === 'tls' ? sni : undefined,
    alpn: security === 'tls' ? alpn : undefined,
    fp: security === 'tls' ? fp : undefined
  };

  const encoded = Buffer.from(JSON.stringify(vmessObj)).toString('base64');
  return `vmess://${encoded}`;
}

  function buildVlessLink({ host, port, clientId, remark, streamSettings }) {
  const network = ensureString(streamSettings?.network, 'tcp');
  const security = ensureString(streamSettings?.security, 'none');
  const isTls = security === 'tls';
  const wsSettings = streamSettings?.wsSettings || {};
  const wsPath = ensureString(wsSettings?.path, '/');
  const wsHost = ensureString(wsSettings?.headers?.Host, '');
  const tlsSettings = streamSettings?.tlsSettings || {};
  const sni = ensureString(tlsSettings?.serverName, host);
  const alpnVal = Array.isArray(tlsSettings?.alpn) ? tlsSettings.alpn.join(',') : ensureString(tlsSettings?.alpn || '');
  const fpVal = ensureString(tlsSettings?.fingerprint || '');
  const domainHost = deriveDomainHost(streamSettings, host);
  const searchParams = new URLSearchParams();
  searchParams.set('encryption', 'none');
  if (isTls) searchParams.set('security', 'tls');
  if (network === 'ws') searchParams.set('type', 'ws');
  if (wsPath) searchParams.set('path', wsPath);
  if (domainHost) searchParams.set('host', domainHost);
  if (isTls) {
    searchParams.set('sni', sni);
    searchParams.set('alpn', alpnVal);
    searchParams.set('fp', fpVal);
  }

  const hash = encodeURIComponent(remark || 'vless');
  return `vless://${clientId}@${host}:${port}?${searchParams.toString()}#${hash}`;
}

  function buildTrojanLink({ host, port, password, remark, streamSettings, connectHostOverride }) {
    const network = ensureString(streamSettings?.network, 'tcp');
    const security = ensureString(streamSettings?.security, 'none');
    const isTls = security === 'tls';
    const wsSettings = streamSettings?.wsSettings || {};
    const wsPath = ensureString(wsSettings?.path, '/');
    const wsHost = ensureString(wsSettings?.headers?.Host, '');
    const tlsSettings = streamSettings?.tlsSettings || {};
    const sni = ensureString(tlsSettings?.serverName, host);
    const alpnVal = Array.isArray(tlsSettings?.alpn) ? tlsSettings.alpn.join(',') : ensureString(tlsSettings?.alpn || '');
    const fpVal = ensureString(tlsSettings?.fingerprint || '');
    const domainHost = deriveDomainHost(streamSettings, host);
    const params = new URLSearchParams();
    if (isTls) params.set('security', 'tls');
    if (network === 'ws') {
      params.set('type', 'ws');
      if (wsPath) params.set('path', wsPath);
      if (domainHost) params.set('host', domainHost);
    }
    // TLS extras
    if (isTls) {
      params.set('sni', sni);
      params.set('alpn', alpnVal);
      params.set('fp', fpVal);
    }
    const suffix = params.toString() ? `?${params.toString()}` : '';
    const hash = encodeURIComponent(remark || 'trojan');
    const connectHost = connectHostOverride || host;
    return `trojan://${password}@${connectHost}:${port}${suffix}#${hash}`;
  }

  function buildConfigLink(protocol, inbound, createdClient, options = {}) {
  const streamSettings = parseJsonIfString(inbound.streamSettings, {});
  const remark = ensureString(inbound.remark, `${protocol}`);
  const port = inbound.port;
  const host = PUBLIC_HOST;
    const clientId = createdClient.id; // for vmess/vless

  if (protocol === 'vmess') {
    return buildVmessLink({ host, port, clientId, remark, streamSettings });
  }
  if (protocol === 'vless') {
    return buildVlessLink({ host, port, clientId, remark, streamSettings });
  }
    if (protocol === 'trojan') {
      const password = createdClient.password;
      return buildTrojanLink({ host, port, password, remark, streamSettings, connectHostOverride: options.connectHostOverride });
    }
  return 'Protocol tidak didukung untuk pembuatan konfigurasi.';
}

const xui = new XuiClient({
  baseUrl: XUI_BASE_URL,
  username: XUI_USERNAME,
  password: XUI_PASSWORD
});

const bot = new Bot(BOT_TOKEN);
const configTokenToLink = new Map();

const pendingEmailByChatId = new Map();

function buildMainKeyboard(isAdminUser) {
  const kb = new Keyboard()
    .text('Inbounds')
    .text('Saldo')
    .text('Topup')
    .text('Clients');
  if (isAdminUser) kb.row().text('Admin');
  return kb.resized();
}

async function tryAddClientViaUpdate(xui, inboundId, client, ctx) {
  const inboundResp = await xui.getInbound(inboundId);
  const inbound = inboundResp?.obj || inboundResp?.inbound || inboundResp;
  if (!inbound) {
    throw new Error('Inbound tidak ditemukan saat fallback update');
  }
  const settingsObj = parseJsonIfString(inbound.settings, {});
  const clients = Array.isArray(settingsObj.clients) ? [...settingsObj.clients] : [];
  // Pastikan creatorId tersimpan saat menggunakan fallback add client
if (!client.creatorId && ctx?.from?.id) {
    client.creatorId = ctx.from.id;
  }
  clients.push(client);
  settingsObj.clients = clients;
  const streamSettingsStr = typeof inbound.streamSettings === 'string' ? inbound.streamSettings : JSON.stringify(inbound.streamSettings || {});
  const sniffingStr = typeof inbound.sniffing === 'string' ? inbound.sniffing : JSON.stringify(inbound.sniffing || {});

  const payload = {
    up: inbound.up ?? 0,
    down: inbound.down ?? 0,
    total: inbound.total ?? 0,
    remark: inbound.remark ?? '',
    enable: inbound.enable !== false,
    expiryTime: inbound.expiryTime ?? 0,
    listen: inbound.listen ?? '',
    port: inbound.port,
    protocol: inbound.protocol,
    tag: inbound.tag ?? '',
    sniffing: sniffingStr,
    streamSettings: streamSettingsStr,
    settings: JSON.stringify(settingsObj)
  };

  const upd = await xui.updateInbound(inboundId, payload);
  if (!upd || upd?.success === false) {
    const details = upd?.msg || upd?.raw || JSON.stringify(upd || {});
    throw new Error(`Fallback update gagal: ${details}`);
  }
  return true;
}

async function tryRemoveClientViaUpdate(xui, inboundId, clientKey) {
  const inboundResp = await xui.getInbound(inboundId);
  const inbound = inboundResp?.obj || inboundResp?.inbound || inboundResp;
  if (!inbound) {
    throw new Error('Inbound tidak ditemukan saat fallback hapus');
  }
  const settingsObj = parseJsonIfString(inbound.settings, {});
  const clients = Array.isArray(settingsObj.clients) ? settingsObj.clients : [];
  const before = clients.length;
  const filtered = clients.filter((c) => c.id !== clientKey && c.password !== clientKey && c.email !== clientKey);
  if (filtered.length === before) {
    throw new Error('Client tidak ditemukan pada inbound ini');
  }
  settingsObj.clients = filtered;

  const streamSettingsStr = typeof inbound.streamSettings === 'string' ? inbound.streamSettings : JSON.stringify(inbound.streamSettings || {});
  const sniffingStr = typeof inbound.sniffing === 'string' ? inbound.sniffing : JSON.stringify(inbound.sniffing || {});

  const payload = {
    up: inbound.up ?? 0,
    down: inbound.down ?? 0,
    total: inbound.total ?? 0,
    remark: inbound.remark ?? '',
    enable: inbound.enable !== false,
    expiryTime: inbound.expiryTime ?? 0,
    listen: inbound.listen ?? '',
    port: inbound.port,
    protocol: inbound.protocol,
    tag: inbound.tag ?? '',
    sniffing: sniffingStr,
    streamSettings: streamSettingsStr,
    settings: JSON.stringify(settingsObj)
  };

  const upd = await xui.updateInbound(inboundId, payload);
  if (!upd || upd?.success === false) {
    const details = upd?.msg || upd?.raw || JSON.stringify(upd || {});
    throw new Error(`Fallback hapus gagal: ${details}`);
  }
  return true;
}

bot.command('start', async (ctx) => {
  const keyboard = new InlineKeyboard().text('Daftar Inbound Aktif', 'list_inbounds');
  const isAdminUser = isAdmin(ctx.from?.id);
  await ctx.reply('Selamat datang di Oodana Store! ', { reply_markup: buildMainKeyboard(isAdminUser) });
  await ctx.reply('Gunakan tombol di bawah atau pilih menu inline.', { reply_markup: keyboard });
});

bot.command('admin', async (ctx) => {
  if (!isAdmin(ctx.from?.id)) return;
  const kb = new InlineKeyboard()
    .text('Hapus Client', 'admin_del_flow')
    .row()
    .text('Tambah Saldo', 'admin_add_balance')
    .row()
    .text('Verifikasi Topup', 'admin_list_topups')
    .row()
    .text('Lihat Log', 'admin_logs')
    .row()
    .text('List Clients', 'admin_list_clients')
    .row()
    .text('Kelola BUG', 'admin_manage_bugs');
  await ctx.reply('Menu Admin:', { reply_markup: kb });
});

bot.command('saldo', async (ctx) => {
  const bal = getBalance(ctx.from?.id || 0);
  await ctx.reply(`Saldo Anda: Rp ${formatIDR(bal)}\nTarif: 3 hari Rp ${formatIDR(PRICE_BY_DAYS[3])}, 7 hari Rp ${formatIDR(PRICE_BY_DAYS[7])}, 30 hari Rp ${formatIDR(PRICE_BY_DAYS[30])}`);
});

bot.command('clients', async (ctx) => {
  await sendClientsList(ctx, { isAdminView: isAdmin(ctx.from?.id) });
});

bot.command('topup', async (ctx) => {
  const parts = (ctx.message.text || '').trim().split(/\s+/);
  // Admin mode: /topup <telegram_id> <amount>
  if (isAdmin(ctx.from?.id)) {
    if (parts.length < 3) {
      await ctx.reply('Format admin: /topup <telegram_id> <jumlah>. Contoh: /topup 123456789 10000');
      return;
    }
    const targetId = Number(parts[1]);
    const amount = Number(parts[2]);
    if (!Number.isFinite(targetId) || !Number.isFinite(amount) || amount <= 0) {
      await ctx.reply('Parameter tidak valid. Contoh: /topup 123456789 10000');
      return;
    }
    const newBal = addBalance(targetId, amount);
    await ctx.reply(`Topup berhasil. Saldo user ${targetId} sekarang: Rp ${formatIDR(newBal)}`);
    logEvent({ type: 'topup_admin_add', actorId: ctx.from?.id || 0, targetUserId: targetId, amount });
    return;
  }

  // User mode: /topup <nominal> (total = nominal + kode unik acak 1..100)
  if (parts.length < 2) {
    await ctx.reply(`Topup mandiri:
Kirim perintah /topup <nominal>. Contoh: /topup 1000
Sistem akan menambahkan kode unik acak (1..100) ke nominal Anda.\n
Metode pembayaran: ${PAYMENT_INFO}
Setelah transfer, kirim bukti/nomor referensi via /ref <ID> <kode_ref>.`);
    return;
  }
  const nominal = Number(parts[1]);
  if (!Number.isFinite(nominal) || nominal <= 0) {
    await ctx.reply('Nominal tidak valid. Contoh: /topup 1000');
    return;
  }
  const uniqueCode = Math.max(1, Math.min(100, Math.floor(Math.random() * 100) + 1));
  const fullAmount = nominal + uniqueCode;
  const req = createTopupRequest(ctx.from?.id || 0, fullAmount, uniqueCode);
  logEvent({ type: 'topup_request', userId: ctx.from?.id || 0, id: req.id, total: fullAmount, uniqueCode });
  const kb = new InlineKeyboard().text('Kirim Permintaan Topup', `ref_tpl_${encodeURIComponent(req.id)}`);
  await ctx.reply(`Permintaan topup dibuat.
ID: ${req.id}
Nominal: Rp ${formatIDR(nominal)}
Kode unik acak: ${uniqueCode}
Total transfer: Rp ${formatIDR(fullAmount)}
Bayar ke: ${PAYMENT_INFO}

Salin perintah berikut dan ganti KODE_REF setelah transfer:

/ref ${req.id} KODE_REF`, { reply_markup: kb });
  // Notify admins bahwa ada permintaan topup baru (pending)
  const adminKb = new InlineKeyboard().text('Verifikasi Topup', 'admin_list_topups');
  for (const adminId of ADMIN_TELEGRAM_IDS) {
    try {
      const sent = await bot.api.sendMessage(
        adminId,
        `Permintaan topup baru (pending):\nID: ${req.id}\nUser: ${ctx.from?.id}\nNominal: Rp ${formatIDR(nominal)}\nKode unik: ${uniqueCode}\nTotal: Rp ${formatIDR(fullAmount)}\nBerlaku hingga: ${new Date(readTopups().find(t=>t.id===req.id)?.expiresAt || (Date.now()+TOPUP_TTL_MS)).toLocaleTimeString()} (TTL 5 menit)`,
        { reply_markup: adminKb }
      );
      addTopupAdminNotif(req.id, sent.chat.id, sent.message_id);
    } catch {}
  }
});

bot.command('ref', async (ctx) => {
  const parts = (ctx.message.text || '').trim().split(/\s+/);
  // /ref <request_id> <kode_ref>
  if (parts.length < 3) {
    await ctx.reply('Format: /ref <ID_TOPUP> <KODE_REF>. Contoh: /ref 1710000000000-123456789 ABC123');
    return;
  }
  const requestId = parts[1];
  const kode = parts.slice(2).join(' ');
  // check expiry
  const reqEntry = readTopups().find((t) => t.id === requestId);
  if (!reqEntry || reqEntry.status !== 'pending') {
    await ctx.reply('ID topup tidak valid atau sudah diproses.');
    return;
  }
  if (Date.now() > Number(reqEntry.expiresAt || 0)) {
    // expire: delete admin notifs and mark expired
    const notifs = popTopupAdminNotifs(requestId);
    for (const n of notifs) {
      try { await bot.api.deleteMessage(n.chatId, n.messageId); } catch {}
    }
    updateTopupStatus(requestId, 'expired');
    await ctx.reply('Sesi topup sudah kedaluwarsa (lebih dari 5 menit). Mohon buat permintaan topup baru.');
    return;
  }
  const updated = updateTopupStatus(requestId, 'waiting-verify');
  if (!updated) {
    await ctx.reply('ID topup tidak ditemukan.');
    return;
  }
  logEvent({ type: 'topup_ref', userId: ctx.from?.id || 0, id: requestId, ref: kode });
  await ctx.reply('Terima kasih, menunggu verifikasi admin.');
  // Notify admins dengan tombol Approve/Reject
  const adminKb = new InlineKeyboard()
    .text('Approve', `topup_ok_${encodeURIComponent(requestId)}`)
    .text('Reject', `topup_no_${encodeURIComponent(requestId)}`);
  for (const adminId of ADMIN_TELEGRAM_IDS) {
    try {
      await bot.api.sendMessage(
        adminId,
        `Topup menunggu verifikasi:\nID: ${requestId}\nUser: ${updated.userId}\nJumlah: Rp ${formatIDR(updated.amount)}\nREF: ${kode}`,
        { reply_markup: adminKb }
      );
    } catch {}
  }
});

bot.command('verif', async (ctx) => {
  if (!isAdmin(ctx.from?.id)) return;
  const parts = (ctx.message.text || '').trim().split(/\s+/);
  // /verif <request_id> approve|reject
  if (parts.length < 3) {
    await ctx.reply('Format: /verif <ID_TOPUP> <approve|reject>');
    return;
  }
  const requestId = parts[1];
  const action = String(parts[2]).toLowerCase();
  const entry = readTopups().find((t) => t.id === requestId);
  if (!entry) {
    await ctx.reply('ID topup tidak ditemukan.');
    return;
  }
  if (action === 'approve') {
    updateTopupStatus(requestId, 'approved');
    const newBal = addBalance(entry.userId, entry.amount);
    await ctx.reply(`Approved. Saldo user ${entry.userId} bertambah Rp ${formatIDR(entry.amount)} (saldo sekarang Rp ${formatIDR(newBal)}).`);
    try { await bot.api.sendMessage(entry.userId, `Topup disetujui. Saldo +Rp ${formatIDR(entry.amount)}. Saldo sekarang Rp ${formatIDR(newBal)}.`); } catch {}
  } else if (action === 'reject') {
    updateTopupStatus(requestId, 'rejected');
    await ctx.reply('Topup ditolak.');
    try { await bot.api.sendMessage(entry.userId, 'Topup ditolak, silakan hubungi admin bila ada kesalahan.'); } catch {}
  } else {
    await ctx.reply('Aksi tidak dikenal. Gunakan approve atau reject.');
  }
});

bot.callbackQuery('list_inbounds', async (ctx) => {
  await ctx.answerCallbackQuery();
  try {
    await xui.login();
    const data = await xui.listInbounds();
    const items = Array.isArray(data?.obj) ? data.obj : Array.isArray(data?.inbounds) ? data.inbounds : [];

    const supported = items.filter((it) => it?.enable && (it?.protocol === 'vmess' || it?.protocol === 'vless' || it?.protocol === 'trojan'));
    if (supported.length === 0) {
      await ctx.reply('Tidak ada inbound aktif (vmess/vless).');
      return;
    }

    const kb = new InlineKeyboard();
    for (const inbound of supported) {
      const label = `${inbound.protocol.toUpperCase()} • ${inbound.remark || 'no-remark'} • :${inbound.port}`;
      kb.text(label, `pick_${inbound.id}`).row();
    }
    await ctx.reply('Pilih inbound:', { reply_markup: kb });
  } catch (err) {
    await ctx.reply(`Gagal memuat inbound: ${err.message}`);
  }
});

bot.on('callback_query:data', async (ctx) => {
  const data = ctx.callbackQuery.data || '';

  if (data.startsWith('pick_')) {
    await ctx.answerCallbackQuery();
    const inboundId = Number(data.slice('pick_'.length));
    if (!Number.isFinite(inboundId)) {
      return ctx.reply('Inbound tidak valid.');
    }
    try {
      // remove previous menu buttons
      try { await ctx.editMessageReplyMarkup({}); } catch {}
      await xui.login();
      const inboundResp = await xui.getInbound(inboundId);
      const inbound = inboundResp?.obj || inboundResp?.inbound || inboundResp;
      if (!inbound?.enable) {
        return ctx.reply('Inbound tidak aktif.');
      }

      const label = `${inbound.protocol?.toUpperCase() || '-'} • ${inbound.remark || 'no-remark'} • :${inbound.port}`;
      const kb = new InlineKeyboard()
        .text('Tambah Client', `add_${inboundId}`)
        .row()
        .text('Batal', 'cancel');
      await ctx.reply(`Inbound terpilih:\n${label}`, { reply_markup: kb });
    } catch (err) {
      await ctx.reply(`Gagal memuat inbound: ${err.message}`);
    }
    return;
  }

  if (data.startsWith('ref_tpl_')) {
    await ctx.answerCallbackQuery();
    const id = decodeURIComponent(data.slice('ref_tpl_'.length));
    await ctx.reply(`/ref ${id} KODE_REF`);
    return;
  }

  if (data.startsWith('add_')) {
    await ctx.answerCallbackQuery();
    const inboundId = Number(data.slice('add_'.length));
    if (!Number.isFinite(inboundId)) {
      return ctx.reply('Inbound tidak valid.');
    }
    try { await ctx.editMessageReplyMarkup({}); } catch {}
    const bal = getBalance(ctx.from?.id || 0);
    await ctx.reply(`Saldo Anda saat ini: Rp ${formatIDR(bal)}\nTarif: 3 hari Rp ${formatIDR(PRICE_BY_DAYS[3])}, 7 hari Rp ${formatIDR(PRICE_BY_DAYS[7])}, 30 hari Rp ${formatIDR(PRICE_BY_DAYS[30])}`);
    const kb = new InlineKeyboard()
      .text('3 hari', `dur_3_${inboundId}`).text('7 hari', `dur_7_${inboundId}`).text('30 hari', `dur_30_${inboundId}`)
      .row()
      .text('Batal', 'cancel');
    await ctx.reply('Pilih masa aktif akun:', { reply_markup: kb });
    return;
  }

  if (data === 'admin_del_flow') {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    // keep this menu persistent by not clearing markup here
    const kb = new InlineKeyboard().text('Pilih Inbound', 'list_inbounds_for_del').row().text('Batal', 'cancel');
    await ctx.reply('Hapus Client: pilih inbound terlebih dahulu.', { reply_markup: kb });
    return;
  }

  if (data === 'admin_add_balance') {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    await ctx.reply('Kirim perintah dengan format: /topup <telegram_id> <jumlah>\nContoh: /topup 123456789 10000');
    return;
  }

  if (data === 'admin_list_topups') {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    const pendings = getPendingTopups(20);
    if (pendings.length === 0) {
      await ctx.reply('Tidak ada topup pending.');
      return;
    }
    for (const t of pendings) {
      const kb = new InlineKeyboard()
        .text('Approve', `topup_ok_${encodeURIComponent(t.id)}`)
        .text('Reject', `topup_no_${encodeURIComponent(t.id)}`);
      await ctx.reply(`Topup Pending\nID: ${t.id}\nUser: ${t.userId}\nJumlah: Rp ${formatIDR(t.amount)}`, { reply_markup: kb });
    }
    return;
  }

  if (data === 'admin_logs') {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    const logs = readLogs(20);
    if (logs.length === 0) {
      await ctx.reply('Belum ada log.');
      return;
    }
    const text = logs.map(formatLog).join('\n');
    await ctx.reply(text.slice(0, 4000));
    return;
  }

  if (data === 'admin_list_clients') {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    try {
      await xui.login();
      const list = await xui.listInbounds();
      const items = Array.isArray(list?.obj) ? list.obj : Array.isArray(list?.inbounds) ? list.inbounds : [];
      if (items.length === 0) {
        await ctx.reply('Tidak ada inbound.');
        return;
      }
      for (const inbound of items.slice(0, 10)) {
        const settings = parseJsonIfString(inbound?.settings, {});
        const clients = Array.isArray(settings?.clients) ? settings.clients : [];
        if (clients.length === 0) continue;
        for (const c of clients.slice(0, 20)) {
          const proto = inbound.protocol;
          const conf = buildConfigLink(proto, inbound, c);
          const header = `${proto.toUpperCase()} • ${inbound.remark || ''} • :${inbound.port}`;
          const email = c.email || '';
          const expiry = c.expiryTime ? new Date(Number(c.expiryTime)).toLocaleString() : '-';
          const kb = new InlineKeyboard()
            .text('+3d (3000)', `renew_${inbound.id}_${encodeURIComponent(c.id || c.password || c.email)}_3`)
            .text('+7d (6000)', `renew_${inbound.id}_${encodeURIComponent(c.id || c.password || c.email)}_7`)
            .text('+30d (10000)', `renew_${inbound.id}_${encodeURIComponent(c.id || c.password || c.email)}_30`)
            .row()
            .text('Aktif/Nonaktif', `toggle_${inbound.id}_${encodeURIComponent(c.id || c.password || c.email)}`);
          try {
            await ctx.reply(`Inbound: ${header}\nEmail: ${email}\nExpiry: ${expiry}\nConfig:\n\n<code>${escapeHtml(conf)}</code>`, { parse_mode: 'HTML', reply_markup: kb });
          } catch {
            await ctx.reply(`Inbound: ${header}\nEmail: ${email}\nExpiry: ${expiry}\nConfig:\n\n${conf}`, { reply_markup: kb });
          }
        }
      }
    } catch (err) {
      await ctx.reply(`Gagal memuat clients: ${err.message}`);
    }
    return;
  }

  if (data === 'admin_manage_bugs') {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    const bugs = readBugs();
    const kb = new InlineKeyboard();
    for (const host of bugs.slice(0, 10)) kb.text(`Hapus ${host}`, `bugdel_${encodeURIComponent(host)}`).row();
    kb.text('Tambah BUG', 'bugadd_prompt').row().text('Tutup', 'cancel');
    await ctx.reply(`Daftar BUG saat ini:\n${bugs.join(', ') || '-'}`, { reply_markup: kb });
    return;
  }

  if (data.startsWith('bugdel_')) {
    if (!isAdmin(ctx.from?.id)) return ctx.answerCallbackQuery();
    await ctx.answerCallbackQuery();
    const host = decodeURIComponent(data.slice('bugdel_'.length));
    removeBugHost(host);
    await ctx.reply(`BUG dihapus: ${host}`);
    return;
  }

  if (data === 'bugadd_prompt') {
    if (!isAdmin(ctx.from?.id)) return ctx.answerCallbackQuery();
    await ctx.answerCallbackQuery();
    pendingEmailByChatId.set(ctx.chat.id, { bugAddMode: true });
    await ctx.reply('Kirim domain BUG baru (misal: quiz.int.vidio.com).');
    return;
  }

  if (data.startsWith('topup_ok_') || data.startsWith('topup_no_')) {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    const isApprove = data.startsWith('topup_ok_');
    const id = decodeURIComponent(data.slice(isApprove ? 'topup_ok_'.length : 'topup_no_'.length));
    const entry = readTopups().find((t) => t.id === id);
    if (!entry) {
      await ctx.reply('ID topup tidak ditemukan.');
      return;
    }
    // If already processed, just try to remove keyboard/card
    if (entry.status !== 'pending') {
      try {
        const chatId = ctx.chat?.id;
        const msgId = ctx.callbackQuery?.message?.message_id;
        if (chatId && msgId) await ctx.api.deleteMessage(chatId, msgId);
      } catch {}
      try { await ctx.editMessageReplyMarkup({}); } catch {}
      return;
    }
    if (isApprove) {
      updateTopupStatus(id, 'approved');
      const newBal = addBalance(entry.userId, entry.amount);
      logEvent({ type: 'topup_approved', actorId: ctx.from?.id || 0, id, targetUserId: entry.userId, amount: entry.amount });
      await ctx.reply(`Approved. Saldo user ${entry.userId} +Rp ${formatIDR(entry.amount)} (saldo sekarang Rp ${formatIDR(newBal)}).`);
      try { await bot.api.sendMessage(entry.userId, `Topup disetujui. Saldo +Rp ${formatIDR(entry.amount)}. Saldo sekarang Rp ${formatIDR(newBal)}.`); } catch {}
    } else {
      updateTopupStatus(id, 'rejected');
      logEvent({ type: 'topup_rejected', actorId: ctx.from?.id || 0, id, targetUserId: entry.userId });
      await ctx.reply('Topup ditolak.');
      try { await bot.api.sendMessage(entry.userId, 'Topup ditolak, silakan hubungi admin bila ada kesalahan.'); } catch {}
    }
    // Hapus form konfirmasi agar tidak ditekan ulang
    try {
      const chatId = ctx.chat?.id;
      const msgId = ctx.callbackQuery?.message?.message_id;
      if (chatId && msgId) await ctx.api.deleteMessage(chatId, msgId);
    } catch {}
    try { await ctx.editMessageReplyMarkup({}); } catch {}
    // Hapus juga notifikasi pending yang pernah dikirim ke admin lain
    const notifs = popTopupAdminNotifs(id);
    for (const n of notifs) {
      try { await bot.api.deleteMessage(n.chatId, n.messageId); } catch {}
    }
    return;
  }

  if (data === 'list_inbounds_for_del') {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    // Keep deletion flow menus as is (do not clear)
    try {
      await xui.login();
      const dataInb = await xui.listInbounds();
      const items = Array.isArray(dataInb?.obj) ? dataInb.obj : Array.isArray(dataInb?.inbounds) ? dataInb.inbounds : [];
      const supported = items.filter((it) => it?.enable);
      if (supported.length === 0) {
        await ctx.reply('Tidak ada inbound aktif.');
        return;
      }
      const kb = new InlineKeyboard();
      for (const inbound of supported) {
        const label = `${inbound.protocol.toUpperCase()} • ${inbound.remark || 'no-remark'} • :${inbound.port}`;
        kb.text(label, `delpick_${inbound.id}`).row();
      }
      await ctx.reply('Pilih inbound untuk hapus client:', { reply_markup: kb });
    } catch (err) {
      await ctx.reply(`Gagal memuat inbound: ${err.message}`);
    }
    return;
  }

  if (data.startsWith('delpick_')) {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    const inboundId = Number(data.slice('delpick_'.length));
    if (!Number.isFinite(inboundId)) return ctx.reply('Inbound tidak valid.');
    try {
      await xui.login();
      const inboundResp = await xui.getInbound(inboundId);
      const inbound = inboundResp?.obj || inboundResp?.inbound || inboundResp;
      const settings = parseJsonIfString(inbound?.settings, {});
      const clients = Array.isArray(settings?.clients) ? settings.clients : [];
      if (clients.length === 0) {
        await ctx.reply('Tidak ada client pada inbound ini.');
        return;
      }
      const kb = new InlineKeyboard();
      for (const c of clients.slice(0, 30)) { // batasi 30 tombol
        const label = `${c.email || c.id || c.password}`;
        // clientId field sesuai protokol (vmess/vless pakai id, trojan pakai password)
        const clientId = c.id || c.password || c.email;
        kb.text(label, `delcli_${inboundId}_${encodeURIComponent(clientId)}`).row();
      }
      await ctx.reply('Pilih client untuk dihapus:', { reply_markup: kb });
    } catch (err) {
      await ctx.reply(`Gagal memuat clients: ${err.message}`);
    }
    return;
  }

  if (data.startsWith('delcli_')) {
    if (!isAdmin(ctx.from?.id)) {
      await ctx.answerCallbackQuery({ text: 'Akses ditolak', show_alert: true });
      return;
    }
    await ctx.answerCallbackQuery();
    const parts = data.split('_');
    const inboundId = Number(parts[1]);
    const clientId = decodeURIComponent(parts.slice(2).join('_'));
    if (!Number.isFinite(inboundId) || !clientId) return ctx.reply('Data hapus tidak valid.');
    try {
      await xui.login();
      const res = await xui.delClient(inboundId, clientId);
      if (!res || res.success === false) {
        // Fallback: update inbound menimpa daftar clients tanpa client tsb
        await tryRemoveClientViaUpdate(xui, inboundId, clientId);
        await ctx.reply('Client berhasil dihapus (fallback).');
        return;
      }
      await ctx.reply('Client berhasil dihapus.');
    } catch (err) {
      // Fallback terakhir via update
      try {
        await tryRemoveClientViaUpdate(xui, inboundId, clientId);
        await ctx.reply('Client berhasil dihapus (fallback).');
      } catch (err2) {
        await ctx.reply(`Gagal menghapus client: ${err2.message}`);
      }
    }
    logEvent({ type: 'client_deleted', actorId: ctx.from?.id || 0, inboundId, clientKey: clientId });
    return;
  }
  if (data.startsWith('dur_')) {
    await ctx.answerCallbackQuery();
    const parts = data.split('_');
    // format: dur_{days}_{id}
    const days = Number(parts[1]);
    const inboundId = Number(parts[2]);
    if (!Number.isFinite(days) || !Number.isFinite(inboundId)) {
      return ctx.reply('Pilihan masa aktif tidak valid.');
    }
    try { await ctx.editMessageReplyMarkup({}); } catch {}
    const price = PRICE_BY_DAYS[days] || 0;
    const bal = getBalance(ctx.from?.id || 0);
    if (!canBypassSaldo(ctx.from?.id) && bal < price) {
      await ctx.reply(`Saldo tidak cukup. Diperlukan Rp ${formatIDR(price)}. Saldo Anda Rp ${formatIDR(bal)}. Gunakan /saldo untuk cek saldo.`);
      return;
    }
    pendingEmailByChatId.set(ctx.chat.id, { inboundId, days });
    const bugs = readBugs();
    const kb = new InlineKeyboard().text('Tanpa BUG', `bug_none_${inboundId}`);
    for (const host of bugs.slice(0, 6)) kb.text(host, `bug_custom_${inboundId}_${encodeURIComponent(host)}`);
    kb.row().text('Batal', 'cancel');
    await ctx.reply('Pilih BUG (SNI) untuk koneksi trojan (opsional):', { reply_markup: kb });
    return;
  }

  if (data.startsWith('bug_')) {
    await ctx.answerCallbackQuery();
    const parts = data.split('_');
    // bug_{type}_{inboundId}
    const type = parts[1];
    const inboundId = Number(parts[2]);
    if (!Number.isFinite(inboundId)) return ctx.reply('Pilihan tidak valid.');
    let bugHost = '';
    if (type === 'custom') bugHost = decodeURIComponent(parts.slice(2).join('_').replace(/^\d+_/, ''));
    // type none => empty bugHost (no override)
    const prev = pendingEmailByChatId.get(ctx.chat.id) || {};
    pendingEmailByChatId.set(ctx.chat.id, { ...prev, inboundId, bugHost });
    try { await ctx.editMessageReplyMarkup({}); } catch {}
    const kb = new InlineKeyboard().text('Batal', 'cancel');
    await ctx.reply(`Kirim username saja (tanpa @). Domain otomatis @${STATIC_EMAIL_DOMAIN}.\nContoh: user1`, { reply_markup: kb });
    return;
  }

  if (data.startsWith('copy_')) {
    await ctx.answerCallbackQuery();
    const token = data.slice('copy_'.length);
    const link = configTokenToLink.get(token);
    if (!link) {
      await ctx.reply('Config tidak ditemukan atau sudah kedaluwarsa.');
      return;
    }
    try {
      try { await ctx.editMessageReplyMarkup({}); } catch {}
      await ctx.reply(`<code>${escapeHtml(link)}</code>`, { parse_mode: 'HTML' });
    } catch {
      await ctx.reply(link);
    }
    configTokenToLink.delete(token);
    return;
  }

  if (data.startsWith('renew_')) {
    await ctx.answerCallbackQuery();
    try { await ctx.editMessageReplyMarkup({}); } catch {}
    const parts = data.split('_');
    const inboundId = Number(parts[1]);
    const rest = parts.slice(2).join('_');
    const [encodedKey, daysStr] = rest.split('_');
    const clientKey = decodeURIComponent(encodedKey);
    const addDays = Number(daysStr);
    try {
      // saldo deduction for renew (non-admin users)
      const cost = PRICE_BY_DAYS[addDays] || 0;
      let refunded = false;
      if (cost > 0 && !canBypassSaldo(ctx.from?.id)) {
        const res = deductBalance(ctx.from?.id || 0, cost);
        if (!res.ok) {
          await ctx.reply(`Saldo tidak cukup. Diperlukan Rp ${formatIDR(cost)}. Saldo Anda Rp ${formatIDR(res.balance)}.`);
          return;
        }
      }
      await xui.login();
      const inboundResp = await xui.getInbound(inboundId);
      const inbound = inboundResp?.obj || inboundResp?.inbound || inboundResp;
      const settingsObj = parseJsonIfString(inbound?.settings, {});
      const clients = Array.isArray(settingsObj?.clients) ? settingsObj.clients : [];
      const idx = clients.findIndex((c) => (c.id || c.password || c.email) === clientKey);
      if (idx === -1) return await ctx.reply('Client tidak ditemukan.');
      const cur = { ...clients[idx] };
      const now = Date.now();
      const base = Number(cur.expiryTime || 0) > now ? Number(cur.expiryTime) : now;
      const updated = { ...cur, expiryTime: base + addDays * 24 * 60 * 60 * 1000 };
      clients[idx] = updated;
      settingsObj.clients = clients;
      const payload = {
        up: inbound.up ?? 0,
        down: inbound.down ?? 0,
        total: inbound.total ?? 0,
        remark: inbound.remark ?? '',
        enable: inbound.enable !== false,
        expiryTime: inbound.expiryTime ?? 0,
        listen: inbound.listen ?? '',
        port: inbound.port,
        protocol: inbound.protocol,
        tag: inbound.tag ?? '',
        sniffing: typeof inbound.sniffing === 'string' ? inbound.sniffing : JSON.stringify(inbound.sniffing || {}),
        streamSettings: typeof inbound.streamSettings === 'string' ? inbound.streamSettings : JSON.stringify(inbound.streamSettings || {}),
        settings: JSON.stringify(settingsObj)
      };
      const r = await xui.updateInbound(inboundId, payload);
      if (r && r.success === false) throw new Error(r.msg || 'Gagal update');
      if (cost > 0 && !canBypassSaldo(ctx.from?.id)) {
        const bal = getBalance(ctx.from?.id || 0);
        await ctx.reply(`Masa aktif diperpanjang +${addDays} hari. Biaya Rp ${formatIDR(cost)} telah dipotong. Berlaku hingga ${new Date(updated.expiryTime).toLocaleString()}.\nSisa saldo: Rp ${formatIDR(bal)}`);
      } else {
        await ctx.reply(`Masa aktif diperpanjang +${addDays} hari. Berlaku hingga ${new Date(updated.expiryTime).toLocaleString()}.`);
      }
    } catch (e) {
      // refund on failure if we deducted earlier
      const cost = PRICE_BY_DAYS[addDays] || 0;
      if (cost > 0 && !canBypassSaldo(ctx.from?.id)) addBalance(ctx.from?.id || 0, cost);
      await ctx.reply(`Gagal memperpanjang: ${e.message}`);
    }
    return;
  }

  if (data.startsWith('toggle_')) {
    await ctx.answerCallbackQuery();
    try { await ctx.editMessageReplyMarkup({}); } catch {}
    const parts = data.split('_');
    const inboundId = Number(parts[1]);
    const clientKey = decodeURIComponent(parts.slice(2).join('_'));
    try {
      await xui.login();
      const inboundResp = await xui.getInbound(inboundId);
      const inbound = inboundResp?.obj || inboundResp?.inbound || inboundResp;
      const settingsObj = parseJsonIfString(inbound?.settings, {});
      const clients = Array.isArray(settingsObj?.clients) ? settingsObj.clients : [];
      const idx = clients.findIndex((c) => (c.id || c.password || c.email) === clientKey);
      if (idx === -1) return await ctx.reply('Client tidak ditemukan.');
      const cur = { ...clients[idx] };
      const updated = { ...cur, enable: cur.enable === false ? true : false };
      clients[idx] = updated;
      settingsObj.clients = clients;
      const payload = {
        up: inbound.up ?? 0,
        down: inbound.down ?? 0,
        total: inbound.total ?? 0,
        remark: inbound.remark ?? '',
        enable: inbound.enable !== false,
        expiryTime: inbound.expiryTime ?? 0,
        listen: inbound.listen ?? '',
        port: inbound.port,
        protocol: inbound.protocol,
        tag: inbound.tag ?? '',
        sniffing: typeof inbound.sniffing === 'string' ? inbound.sniffing : JSON.stringify(inbound.sniffing || {}),
        streamSettings: typeof inbound.streamSettings === 'string' ? inbound.streamSettings : JSON.stringify(inbound.streamSettings || {}),
        settings: JSON.stringify(settingsObj)
      };
      const r = await xui.updateInbound(inboundId, payload);
      if (r && r.success === false) throw new Error(r.msg || 'Gagal update');
      await ctx.reply(`Client ${updated.enable ? 'diaktifkan' : 'dinonaktifkan'}.`);
    } catch (e) {
      await ctx.reply(`Gagal mengubah status client: ${e.message}`);
    }
    return;
  }

  return ctx.answerCallbackQuery();
});

bot.callbackQuery('cancel', async (ctx) => {
  await ctx.answerCallbackQuery();
  pendingEmailByChatId.delete(ctx.chat.id);
  await ctx.reply('Dibatalkan. Gunakan /start untuk mulai lagi.');
});

bot.on('message:text', async (ctx) => {
  // Handle main reply-keyboard buttons
  const text = (ctx.message.text || '').trim().toLowerCase();
  if (text === 'inbounds') {
    await bot.api.sendMessage(ctx.chat.id, 'Memuat inbounds...', { reply_markup: new InlineKeyboard().text('Daftar Inbound Aktif', 'list_inbounds') });
    return;
  }
  if (text === 'clients') {
    // fall back to /clients
    ctx.message.text = '/clients';
  }
  if (text === 'saldo') {
    const bal = getBalance(ctx.from?.id || 0);
    await ctx.reply(`Saldo Anda: Rp ${formatIDR(bal)}\nTarif: 3 hari Rp ${formatIDR(PRICE_BY_DAYS[3])}, 7 hari Rp ${formatIDR(PRICE_BY_DAYS[7])}, 30 hari Rp ${formatIDR(PRICE_BY_DAYS[30])}`);
    return;
  }
  if (text === 'topup') {
    await ctx.reply(`Topup mandiri:\nKirim perintah /topup <nominal>. Contoh: /topup 1000\nSistem akan menambahkan kode unik acak (1..100) ke nominal Anda.\n\nMetode pembayaran: ${PAYMENT_INFO}\nSetelah transfer, kirim bukti/nomor referensi via /ref <ID> <kode_ref>.`);
    return;
  }
  if (text === 'clients') {
    await sendClientsList(ctx, { isAdminView: isAdmin(ctx.from?.id) });
    return;
  }
  if (text === 'admin' && isAdmin(ctx.from?.id)) {
    const kb = new InlineKeyboard()
      .text('Hapus Client', 'admin_del_flow')
      .row()
      .text('Tambah Saldo', 'admin_add_balance')
      .row()
      .text('Verifikasi Topup', 'admin_list_topups');
    await ctx.reply('Menu Admin:', { reply_markup: kb });
    return;
  }

  const pending = pendingEmailByChatId.get(ctx.chat.id);
  if (!pending) return; // ignore normal chat

  if (pending.bugAddMode) {
    const host = (ctx.message.text || '').trim();
    if (!host) {
      await ctx.reply('Domain tidak boleh kosong.');
      return;
    }
    addBugHost(host);
    pendingEmailByChatId.delete(ctx.chat.id);
    await ctx.reply(`BUG ditambahkan: ${host}`);
    return;
  }

  const email = makeEmailFromUserInput(ctx.message.text || '');
  if (!email) {
    await ctx.reply(`Username tidak boleh kosong. Contoh: user1 → email menjadi user1@${STATIC_EMAIL_DOMAIN}`);
    return;
  }

  try {
    await xui.login();
    const inboundResp = await xui.getInbound(pending.inboundId);
    const inbound = inboundResp?.obj || inboundResp?.inbound || inboundResp;
    const protocol = inbound?.protocol;
    if (protocol !== 'vmess' && protocol !== 'vless' && protocol !== 'trojan') {
      await ctx.reply('Hanya vmess/vless/trojan yang didukung.');
      pendingEmailByChatId.delete(ctx.chat.id);
      return;
    }

    const uuid = global.crypto?.randomUUID ? global.crypto.randomUUID() : require('crypto').randomUUID();
    let client;
    if (protocol === 'trojan') {
      const password = uuid.replace(/-/g, '');
      client = { password, email, enable: true, creatorId: ctx.from?.id || 0 };
    } else {
      client = { id: uuid, email, enable: true, creatorId: ctx.from?.id || 0 };
    }

    // Handle masa aktif (expiryTime per-client) bila panel mendukung pada settings.clients[*].expiryTime
    const days = Number(pending.days || 0);
    let clientExpiryMs = 0;
    if (Number.isFinite(days) && days > 0) {
      clientExpiryMs = Date.now() + days * 24 * 60 * 60 * 1000;
      // beberapa panel memakai detik; namun 3x-ui client expiry umumnya ms (ikut panel). Kita simpan di property khusus jika tersedia saat update fallback
      client.expiryTime = clientExpiryMs;
    }

    // Deduct saldo saat akan membuat client (berdasarkan days yang dipilih)
    const cost = PRICE_BY_DAYS[days] || 0;
    if (cost > 0 && !canBypassSaldo(ctx.from?.id)) {
      const res = deductBalance(ctx.from?.id || 0, cost);
      if (!res.ok) {
        await ctx.reply(`Saldo tidak cukup. Diperlukan Rp ${formatIDR(cost)}. Saldo Anda Rp ${formatIDR(res.balance)}.`);
        pendingEmailByChatId.delete(ctx.chat.id);
        return;
      }
    }

    let addResp = await xui.addClient(pending.inboundId, client);
    if (!addResp || addResp?.success === false) {
      // Fallback terakhir: update inbound dengan menambahkan client ke settings
      await tryAddClientViaUpdate(xui, pending.inboundId, client, ctx);
      addResp = { success: true };
    }

    const refreshed = await xui.getInbound(pending.inboundId);
    const inboundAfter = refreshed?.obj || refreshed?.inbound || refreshed;
    const settings = parseJsonIfString(inboundAfter?.settings, {});
    const clients = Array.isArray(settings?.clients) ? settings.clients : [];
    let created = clients.find((c) => c.email === email) || (protocol === 'trojan' ? { password: client.password, email } : { id: uuid, email });
    if (!created.expiryTime && clientExpiryMs) {
      // jika panel tidak menyimpan expiry per-client, set ke remark agar terlihat
      created = { ...created, expiryTime: clientExpiryMs };
    }

    const connectHostOverride = protocol === 'trojan' ? (pending.bugHost || '') : '';
    const link = buildConfigLink(protocol, inboundAfter, created, { connectHostOverride });

    const expText = clientExpiryMs ? `\nMasa aktif: ${days} hari (hingga ${new Date(clientExpiryMs).toLocaleString()})` : '';
    const token = Math.random().toString(36).slice(2, 8);
    configTokenToLink.set(token, link);
    const msg = `Client berhasil dibuat.\n\nProtocol: ${protocol.toUpperCase()}\nEmail: ${email}${expText}\n\nConfig (tap tombol untuk copy):`;
    const copyKb = new InlineKeyboard().text('Salin Config', `copy_${token}`);
    await ctx.reply(msg, { reply_markup: copyKb });
    logEvent({ type: 'client_created', userId: ctx.from?.id || 0, inboundId: pending.inboundId, protocol, email, days });
  } catch (err) {
    // Jika gagal setelah saldo dipotong, kembalikan saldo otomatis
    const pending = pendingEmailByChatId.get(ctx.chat.id);
    const days = Number(pending?.days || 0);
    const cost = PRICE_BY_DAYS[days] || 0;
    if (cost > 0 && !canBypassSaldo(ctx.from?.id)) addBalance(ctx.from?.id || 0, cost);
    await ctx.reply(`Terjadi kesalahan: ${err.message}`);
  } finally {
    pendingEmailByChatId.delete(ctx.chat.id);
  }
});

bot.catch((err) => {
  console.error('Bot error:', err);
});

bot.start();


