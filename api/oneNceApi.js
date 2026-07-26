// 1NCE Management API client — sends AT commands to trackers by SMS.
//
// Two-step flow (as the 1NCE portal documents it):
//   1. POST /management-api/oauth/token  with HTTP Basic user:pass
//        → { access_token, expires_in }   (short-lived, ~10 min)
//   2. POST /management-api/v2/sims/{ICCID}/sms  with Bearer <access_token>
//        → queues an SMS to the SIM
//
// Credentials live ONLY server-side in a gitignored one-nce-mgmt-auth.json
// (or env vars). They are never sent to the browser: the dashboard calls our
// own /send-command, and this module talks to 1NCE.
//
// The token is cached in memory and refreshed automatically shortly before it
// expires, so a burst of sends reuses one token.

const fs = require('fs');
const path = require('path');

const TOKEN_URL = 'https://api.1nce.com/management-api/oauth/token';
const SMS_URL = (iccid) => `https://api.1nce.com/management-api/v2/sims/${encodeURIComponent(iccid)}/sms`;

// Defaults for the SMS envelope. Overridable per-install via the auth file so
// a different source address / type can be set without code changes.
const DEFAULT_SOURCE_ADDRESS = '123456';
const DEFAULT_SOURCE_ADDRESS_TYPE_ID = 145;
const DEFAULT_DCS = 0;

const AUTH_FILE = process.env.ONE_NCE_MGMT_AUTH_FILE ||
  path.join(__dirname, '..', 'one-nce-mgmt-auth.json');

/**
 * Load management-API credentials + optional SMS envelope overrides.
 * Env vars win over the file so the VPS can inject secrets without a file.
 * Returns null when nothing is configured (feature stays disabled, no error).
 */
function loadConfig() {
  let cfg = {};
  try {
    if (fs.existsSync(AUTH_FILE)) cfg = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
  } catch (err) {
    console.error('[1NCE-mgmt] Could not read auth file:', err.message);
  }
  const user = process.env.ONE_NCE_MGMT_USER || cfg.user || cfg.username;
  const pass = process.env.ONE_NCE_MGMT_PASS || cfg.pass || cfg.password;
  if (!user || !pass) return null;
  return {
    user,
    pass,
    sourceAddress: String(cfg.source_address ?? DEFAULT_SOURCE_ADDRESS),
    sourceAddressTypeId: Number(cfg.source_address_type_id ?? DEFAULT_SOURCE_ADDRESS_TYPE_ID),
    dcs: Number(cfg.dcs ?? DEFAULT_DCS),
  };
}

function isConfigured() {
  return loadConfig() !== null;
}

// Build the exact JSON body 1NCE expects for one SMS. Pure — unit-tested.
function buildSmsBody(payload, cfg) {
  return {
    source_address: cfg.sourceAddress,
    payload,
    dcs: cfg.dcs,
    source_address_type: { id: cfg.sourceAddressTypeId },
  };
}

// Validate an AT command before it ever leaves the server. Trackers take
// commands live with no undo, so a malformed string must never be sent.
// Accepts the @Track family: AT+GT…$ (optionally with a trailing newline).
function validateAtCommand(payload) {
  const value = String(payload || '').trim();
  if (!value) return { ok: false, error: 'Command is empty' };
  if (value.length > 300) return { ok: false, error: 'Command is too long (max 300 chars)' };
  if (!/^AT\+GT[A-Z0-9]+=/i.test(value)) {
    return { ok: false, error: 'Command must start with AT+GT…= (a Queclink @Track command)' };
  }
  if (!value.endsWith('$')) return { ok: false, error: 'Command must end with the $ terminator' };
  return { ok: true, value };
}

// ── Token cache ──────────────────────────────────────────────────────────────
let cachedToken = null;      // { token, expiresAt }
const REFRESH_SKEW_MS = 30_000; // refresh 30s before expiry

async function getToken(cfg, { force = false } = {}) {
  if (!force && cachedToken && Date.now() < cachedToken.expiresAt) {
    return cachedToken.token;
  }
  const basic = Buffer.from(`${cfg.user}:${cfg.pass}`).toString('base64');
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Basic ${basic}` },
    body: JSON.stringify({ grant_type: 'client_credentials' }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Token request failed: HTTP ${res.status}${text ? ` — ${text.slice(0, 200)}` : ''}`);
  }
  const data = await res.json();
  if (!data.access_token) throw new Error('Token response missing access_token');
  const ttlMs = (Number(data.expires_in) || 600) * 1000;
  cachedToken = { token: data.access_token, expiresAt: Date.now() + ttlMs - REFRESH_SKEW_MS };
  return cachedToken.token;
}

/**
 * Send one AT command to one SIM (by ICCID). Returns {ok, status, response}.
 * On a 401 the token is force-refreshed once and the send retried, so an
 * expired cached token self-heals rather than failing the send.
 */
async function sendSms(iccid, payload) {
  const cfg = loadConfig();
  if (!cfg) throw new Error('1NCE Management API is not configured');
  const check = validateAtCommand(payload);
  if (!check.ok) throw new Error(check.error);

  const body = JSON.stringify(buildSmsBody(check.value, cfg));

  const attempt = async (token) => fetch(SMS_URL(iccid), {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json;charset=UTF-8',
      Accept: 'application/json',
    },
    body,
  });

  let token = await getToken(cfg);
  let res = await attempt(token);
  if (res.status === 401) {
    token = await getToken(cfg, { force: true });
    res = await attempt(token);
  }

  const text = await res.text().catch(() => '');
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch { /* non-JSON body */ }
  return {
    ok: res.ok,
    status: res.status,
    response: parsed ?? text ?? null,
  };
}

// Test seam: let tests reset the module-level token cache between cases.
function _resetTokenCache() { cachedToken = null; }

module.exports = {
  isConfigured,
  loadConfig,
  buildSmsBody,
  validateAtCommand,
  getToken,
  sendSms,
  _resetTokenCache,
  AUTH_FILE,
};
