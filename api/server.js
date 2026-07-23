const express = require("express");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

const { db, initSchema } = require('./db');
const { runMigration }   = require('./migrate');
const { normalizeRecord, authHeaderFromConfig, secureEqual } = require('./oneNce');

const app  = express();
const PORT = 3010;

const DEVICES_FILE  = process.env.TRACKER_DEVICES_FILE || path.join(__dirname, "..", "devices.json");
const CONFIGS_DIR   = process.env.TRACKER_CONFIGS_DIR || path.join(__dirname, "..", "configs");
const DEPLOYED_DIR  = process.env.TRACKER_DEPLOYED_DIR || path.join(__dirname, "..", "deployed");
const AUTH_FILE     = process.env.TRACKER_AUTH_FILE || path.join(__dirname, "..", "auth.json");
const ONE_NCE_AUTH_FILE = process.env.ONE_NCE_AUTH_FILE || path.join(__dirname, "..", "one-nce-auth.json");
const ONE_NCE_CALLBACK_URL = process.env.ONE_NCE_CALLBACK_URL ||
  'https://1nce.jdwilsh.com/api/1nce/data-streamer';
const TEMPLATES_DIR = process.env.TRACKER_TEMPLATES_DIR || path.join(__dirname, '..', 'templates');
const LOG_FILE      = process.env.TRACKER_LOG_FILE || '/var/log/nginx/cfg.access.log';

// ── Startup ───────────────────────────────────────────────────────────────────
initSchema();
runMigration(db, { DEVICES_FILE, DEPLOYED_DIR, TEMPLATES_DIR, LOG_FILE });

// logWatcher must be required AFTER initSchema (prepared statements need tables)
const { startLogWatcher } = require('./logWatcher');
if (require.main === module && process.env.DISABLE_LOG_WATCHER !== '1') startLogWatcher();

// ── Prepared statements ───────────────────────────────────────────────────────
const stmts = {
  // Trackers summary: latest event per IMEI
  trackerSummary: db.prepare(`
    WITH ranked AS (
      SELECT imei, timestamp, ip, config, status,
             ROW_NUMBER() OVER (PARTITION BY imei ORDER BY timestamp DESC) AS rn
      FROM tracker_events
    )
    SELECT r.imei, r.timestamp AS lastSeen, r.ip AS lastIp,
           r.config AS lastConfig, r.status AS lastStatus,
           d.name
    FROM ranked r
    LEFT JOIN devices d ON d.imei = r.imei
    WHERE r.rn = 1
    ORDER BY r.timestamp DESC
  `),

  // History per tracker (100 most recent)
  trackerHistory: db.prepare(`
    SELECT imei, timestamp, ip, config, status
    FROM tracker_events
    WHERE imei = ?
    ORDER BY timestamp DESC
    LIMIT 100
  `),

  // Paginated history (before cursor)
  trackerHistoryBefore: db.prepare(`
    SELECT imei, timestamp, ip, config, status
    FROM tracker_events
    WHERE imei = ? AND timestamp < ?
    ORDER BY timestamp DESC
    LIMIT ?
  `),

  // Devices
  allDevices:   db.prepare('SELECT imei, name FROM devices'),
  allDeviceDetails: db.prepare(`
    SELECT imei, name, device_type AS deviceType, config_enabled AS configEnabled
    FROM devices ORDER BY name, imei
  `),
  upsertDevice: db.prepare(`
    INSERT INTO devices (imei, name, device_type, config_enabled) VALUES (?, ?, ?, ?)
    ON CONFLICT(imei) DO UPDATE SET
      name = excluded.name,
      device_type = excluded.device_type,
      config_enabled = excluded.config_enabled
  `),
  deleteDevice: db.prepare('DELETE FROM devices WHERE imei = ?'),
  configDevice: db.prepare('SELECT config_enabled AS configEnabled FROM devices WHERE imei = ?'),

  // Deployed states
  getDeployed:    db.prepare('SELECT state_json FROM deployed_states WHERE imei = ?'),
  upsertDeployed: db.prepare(`
    INSERT OR REPLACE INTO deployed_states (imei, state_json, updated_at)
    VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  `),
  getPendingDeployment: db.prepare(`
    SELECT imei, filename, state_json, status, queued_at, downloaded_at
    FROM pending_deployments WHERE imei = ?
  `),
  upsertPendingDeployment: db.prepare(`
    INSERT INTO pending_deployments (imei, filename, state_json, status, queued_at, downloaded_at)
    VALUES (?, ?, ?, 'queued', strftime('%Y-%m-%dT%H:%M:%SZ','now'), NULL)
    ON CONFLICT(imei) DO UPDATE SET
      filename = excluded.filename,
      state_json = excluded.state_json,
      status = 'queued',
      queued_at = excluded.queued_at,
      downloaded_at = NULL
  `),
  markDeploymentDownloaded: db.prepare(`
    UPDATE pending_deployments
    SET status = 'downloaded', downloaded_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
    WHERE imei = ? AND filename = ? AND status = 'queued'
  `),
  deletePendingDeployment: db.prepare(`
    DELETE FROM pending_deployments WHERE imei = ? AND filename = ?
  `),

  // Templates
  allTemplates:    db.prepare('SELECT name FROM templates ORDER BY name'),
  getTemplate:     db.prepare('SELECT state_json FROM templates WHERE name = ?'),
  upsertTemplate:  db.prepare(`
    INSERT OR REPLACE INTO templates (name, state_json, updated_at)
    VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
  `),
  deleteTemplate:  db.prepare('DELETE FROM templates WHERE name = ?'),

  // Settings
  allSettings: db.prepare('SELECT key, value FROM settings'),
  setSetting:  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)'),

  insertSimActivity: db.prepare(`
    INSERT OR IGNORE INTO sim_activity (
      source_record_id, record_kind, event_timestamp, start_timestamp, end_timestamp,
      imei, imsi, iccid, msisdn, traffic_type, event_type, event_severity, is_alert, description,
      operator_name, operator_mnc, country_name, country_mcc, endpoint_ip, apn, rat_type,
      volume_total, volume_tx, volume_rx, cost, currency_code,
      sms_status, sms_payload, sms_source, sms_destination, sms_dcs,
      sms_part_number, sms_total_parts, raw_json, dedupe_key
    ) VALUES (
      @sourceRecordId, @recordKind, @eventTimestamp, @startTimestamp, @endTimestamp,
      @imei, @imsi, @iccid, @msisdn, @trafficType, @eventType, @eventSeverity, @isAlert, @description,
      @operatorName, @operatorMnc, @countryName, @countryMcc, @endpointIp, @apn, @ratType,
      @volumeTotal, @volumeTx, @volumeRx, @cost, @currencyCode,
      @smsStatus, @smsPayload, @smsSource, @smsDestination, @smsDcs,
      @smsPartNumber, @smsTotalParts, @rawJson, @dedupeKey
    )
  `),
  simActivity: db.prepare(`
    SELECT s.id, s.source_record_id AS sourceRecordId, s.record_kind AS recordKind,
           s.received_at AS receivedAt, s.event_timestamp AS eventTimestamp,
           s.start_timestamp AS startTimestamp, s.end_timestamp AS endTimestamp,
           s.imei, s.imsi, s.iccid, s.msisdn, s.traffic_type AS trafficType,
           s.event_type AS eventType, s.event_severity AS eventSeverity,
           s.is_alert AS isAlert, s.description,
           s.operator_name AS operatorName, s.operator_mnc AS operatorMnc,
           s.country_name AS countryName, s.country_mcc AS countryMcc,
           s.endpoint_ip AS endpointIp, s.apn, s.rat_type AS ratType,
           s.volume_total AS volumeTotal, s.volume_tx AS volumeTx,
           s.volume_rx AS volumeRx, s.cost, s.currency_code AS currencyCode,
           s.sms_status AS smsStatus, s.sms_payload AS smsPayload,
           s.sms_source AS smsSource, s.sms_destination AS smsDestination,
           s.sms_dcs AS smsDcs, s.sms_part_number AS smsPartNumber,
           s.sms_total_parts AS smsTotalParts,
           d.name AS deviceName
    FROM sim_activity s
    LEFT JOIN devices d ON d.imei = s.imei
    WHERE (@imei IS NULL OR s.imei = @imei)
      AND (@kind IS NULL OR s.record_kind = @kind)
      AND (@before IS NULL OR COALESCE(s.event_timestamp, s.received_at) < @before)
    ORDER BY COALESCE(s.event_timestamp, s.received_at) DESC, s.id DESC
    LIMIT @limit
  `),
  simActivitySummary: db.prepare(`
    SELECT
      COUNT(*) AS totalRecords,
      COUNT(DISTINCT COALESCE(imei, imsi, iccid)) AS simsSeen,
      COALESCE(SUM(CASE WHEN datetime(received_at) >= datetime('now', '-24 hours') THEN 1 ELSE 0 END), 0) AS records24h,
      COALESCE(SUM(CASE WHEN datetime(received_at) >= datetime('now', '-24 hours') THEN COALESCE(volume_total, 0) ELSE 0 END), 0) AS volume24h,
      COALESCE(SUM(CASE WHEN datetime(received_at) >= datetime('now', '-24 hours')
                AND (is_alert = 1 OR lower(COALESCE(event_severity, ''))
                     IN ('warn','warning','error','critical','high'))
               THEN 1 ELSE 0 END), 0) AS alerts24h,
      MAX(received_at) AS lastReceivedAt
    FROM sim_activity
  `),
  simActivityRaw: db.prepare(`
    SELECT s.id, s.raw_json AS rawJson, s.received_at AS receivedAt, d.name AS deviceName
    FROM sim_activity s LEFT JOIN devices d ON d.imei = s.imei WHERE s.id = ?
  `),
  latestImeiForIccid: db.prepare(`
    SELECT imei FROM sim_activity
    WHERE iccid = ? AND imei IS NOT NULL
    ORDER BY COALESCE(event_timestamp, received_at) DESC, id DESC
    LIMIT 1
  `),
  linkIccidToImei: db.prepare(`
    UPDATE sim_activity SET imei = ? WHERE iccid = ? AND imei IS NULL
  `),
};

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ── Auth ──────────────────────────────────────────────────────────────────────
function loadAuthHash() {
  try {
    if (fs.existsSync(AUTH_FILE))
      return JSON.parse(fs.readFileSync(AUTH_FILE, "utf8")).hash || null;
  } catch {}
  return null;
}

function deriveToken(hash) {
  return crypto.createHmac("sha256", hash).update("tracker-session-v1").digest("hex");
}

function loadOneNceAuthHeader() {
  if (process.env.ONE_NCE_BASIC_AUTH) {
    return authHeaderFromConfig({ token: process.env.ONE_NCE_BASIC_AUTH });
  }
  try {
    if (fs.existsSync(ONE_NCE_AUTH_FILE)) {
      return authHeaderFromConfig(JSON.parse(fs.readFileSync(ONE_NCE_AUTH_FILE, 'utf8')));
    }
  } catch (error) {
    console.error('[1NCE] Could not read auth configuration:', error.message);
  }
  return null;
}

// 1NCE REST streams are authenticated separately from the dashboard. 1NCE sends
// bulk arrays and retries unless the callback responds with HTTP 200.
function receiveOneNce(req, res) {
  const expected = loadOneNceAuthHeader();
  if (!expected) return res.status(503).json({ error: '1NCE receiver is not configured' });
  if (!secureEqual(req.headers.authorization, expected)) {
    res.setHeader('WWW-Authenticate', 'Basic realm="1NCE Data Streamer"');
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const isBulk = Array.isArray(req.body);
  const isSmsObject = req.body && typeof req.body === 'object' && !isBulk;
  if (!isBulk && !isSmsObject) {
    return res.status(400).json({ error: 'Expected a JSON object or bulk array' });
  }
  if (isBulk && req.body.length > 3000) {
    return res.status(413).json({ error: 'Bulk payload exceeds 3000 records' });
  }

  try {
    const payloads = isBulk ? req.body : [req.body];
    const kindHint = req.method === 'PATCH' ? 'sms_mt' : null;
    const records = payloads.map(record => normalizeRecord(record, kindHint));
    const insertMany = db.transaction(items => {
      let inserted = 0;
      for (const record of items) {
        if (!record.imei && record.iccid) {
          record.imei = stmts.latestImeiForIccid.get(record.iccid)?.imei || null;
        }
        inserted += stmts.insertSimActivity.run(record).changes;
        if (record.imei && record.iccid) {
          stmts.linkIccidToImei.run(record.imei, record.iccid);
        }
      }
      return inserted;
    });
    const inserted = insertMany(records);
    return res.status(200).json({
      ok: true,
      received: records.length,
      inserted,
      duplicates: records.length - inserted,
    });
  } catch (error) {
    console.error('[1NCE] Rejected payload:', error.message);
    return res.status(400).json({ error: error.message });
  }
}

app.post(['/1nce/data-streamer', '/api/1nce/data-streamer'], receiveOneNce);
app.patch(['/1nce/data-streamer', '/api/1nce/data-streamer'], receiveOneNce);

app.post("/login", (req, res) => {
  const hash = loadAuthHash();
  if (!hash) return res.json({ token: "dev", warning: "No password set" });
  const submitted = crypto.createHash("sha256")
    .update(req.body.password || "").digest("hex");
  if (submitted !== hash) return res.status(401).json({ error: "Incorrect password" });
  res.json({ token: deriveToken(hash) });
});

app.use((req, res, next) => {
  const hash = loadAuthHash();
  if (!hash) return next();
  const bearer = (req.headers.authorization || "").replace(/^Bearer\s+/, "");
  if (bearer !== deriveToken(hash)) return res.status(401).json({ error: "Unauthorized" });
  next();
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function safeImei(imei) { return /^\d{15}$/.test(imei) ? imei : null; }

function safeName(name) {
  // Allow letters, digits, spaces, dots, hyphens, underscores
  return /^[\w.\- ]+$/.test(name) ? name : null;
}

function safeConfigPath(name) {
  if (!/^[\w.\-]+$/.test(name)) return null;
  const resolved = path.resolve(CONFIGS_DIR, name);
  if (!resolved.startsWith(path.resolve(CONFIGS_DIR) + path.sep) &&
      resolved !== path.resolve(CONFIGS_DIR)) return null;
  return resolved;
}

// ── Auto-cleanup: delete .ini after confirmed delivery ────────────────────────
function cleanupDeliveredConfigs() {
  if (!fs.existsSync(CONFIGS_DIR)) return;
  const rows = stmts.trackerSummary.all();
  for (const tracker of rows) {
    const filename  = `${tracker.imei}.ini`;
    const configPath = safeConfigPath(filename);
    if (!configPath || !fs.existsSync(configPath)) continue;
    let fileMtime;
    try { fileMtime = fs.statSync(configPath).mtimeMs; } catch { continue; }
    if (tracker.lastConfig === filename &&
        tracker.lastStatus === 200 &&
        new Date(tracker.lastSeen).getTime() >= fileMtime) {
      try {
        stmts.markDeploymentDownloaded.run(tracker.imei, filename);
        fs.unlinkSync(configPath);
        console.log(`[cleanup] Marked downloaded and deleted config: ${filename}`);
      } catch (e) {
        console.error(`[cleanup] Failed to delete ${filename}:`, e.message);
      }
    }
  }
}

// ── Routes ────────────────────────────────────────────────────────────────────

app.get("/trackers", (req, res) => {
  cleanupDeliveredConfigs();
  const rows = stmts.trackerSummary.all();
  const result = rows.map(t => {
    const history = stmts.trackerHistory.all(t.imei);
    const deployment = stmts.getPendingDeployment.get(t.imei);
    return {
      imei:          t.imei,
      lastSeen:      t.lastSeen,
      lastIp:        t.lastIp,
      lastConfig:    t.lastConfig,
      lastStatus:    t.lastStatus,
      name:          t.name || null,
      configPending: fs.existsSync(path.join(CONFIGS_DIR, `${t.imei}.ini`)),
      deploymentStatus: deployment ? deployment.status : null,
      deploymentQueuedAt: deployment ? deployment.queued_at : null,
      deploymentDownloadedAt: deployment ? deployment.downloaded_at : null,
      history,
    };
  });
  res.json(result);
});

// Paginated history
app.get("/trackers/:imei/history", (req, res) => {
  const imei = safeImei(req.params.imei);
  if (!imei) return res.status(400).json({ error: "Invalid IMEI" });
  const limit  = Math.min(parseInt(req.query.limit) || 50, 500);
  const before = req.query.before;
  const rows   = before
    ? stmts.trackerHistoryBefore.all(imei, before, limit)
    : stmts.trackerHistory.all(imei).slice(0, limit);
  res.json(rows);
});

// Devices
app.get("/devices", (req, res) => {
  const rows = stmts.allDevices.all();
  const obj  = {};
  for (const r of rows) obj[r.imei] = r.name;
  res.json(obj);
});

app.get('/device-details', (req, res) => {
  res.json(stmts.allDeviceDetails.all().map(device => ({
    ...device,
    configEnabled: Boolean(device.configEnabled),
  })));
});

app.get('/sim-activity', (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 200, 1), 500);
  const imei = req.query.imei ? safeImei(String(req.query.imei)) : null;
  if (req.query.imei && !imei) return res.status(400).json({ error: 'Invalid IMEI' });
  const allowedKinds = new Set(['usage', 'event', 'sms', 'sms_mo', 'sms_mt', 'record']);
  const kind = req.query.kind ? String(req.query.kind) : null;
  if (kind && !allowedKinds.has(kind)) return res.status(400).json({ error: 'Invalid record kind' });
  const before = req.query.before ? String(req.query.before) : null;
  res.json({
    summary: stmts.simActivitySummary.get(),
    records: stmts.simActivity.all({ limit, imei, kind, before }),
    receiver: {
      configured: Boolean(loadOneNceAuthHeader()),
      callbackPath: '/api/1nce/data-streamer',
      callbackUrl: ONE_NCE_CALLBACK_URL,
    },
  });
});

app.get('/sim-activity/:id', (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Invalid record ID' });
  const row = stmts.simActivityRaw.get(id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json({ ...row, raw: JSON.parse(row.rawJson), rawJson: undefined });
});

app.post("/devices", (req, res) => {
  const { imei, name } = req.body;
  if (!safeImei(String(imei || ''))) return res.status(400).json({ error: 'Valid 15-digit IMEI required' });
  if (name && name.trim()) {
    const allowedTypes = new Set(['GL320MG', 'FMM920', 'Other']);
    const deviceType = allowedTypes.has(req.body.deviceType) ? req.body.deviceType : 'GL320MG';
    const configEnabled = deviceType === 'GL320MG' && req.body.configEnabled !== false ? 1 : 0;
    stmts.upsertDevice.run(imei, name.trim(), deviceType, configEnabled);
  } else {
    stmts.deleteDevice.run(imei);
  }
  res.json({ ok: true });
});

app.delete("/devices/:imei", (req, res) => {
  stmts.deleteDevice.run(req.params.imei);
  res.json({ ok: true });
});

// Deployed states
app.get("/deployed/:imei", (req, res) => {
  const imei = safeImei(req.params.imei);
  if (!imei) return res.status(400).json({ error: "Invalid IMEI" });
  const row = stmts.getDeployed.get(imei);
  res.json(row ? JSON.parse(row.state_json) : null);
});

app.post("/deployed/:imei", (req, res) => {
  const imei = safeImei(req.params.imei);
  if (!imei) return res.status(400).json({ error: "Invalid IMEI" });
  const { state } = req.body;
  if (!state || typeof state !== "object") return res.status(400).json({ error: "state required" });
  stmts.upsertDeployed.run(imei, JSON.stringify(state));
  res.json({ ok: true });
});

// Deployment lifecycle: queued state is deliberately separate from confirmed
// state. Writing a file does not mean the tracker has downloaded or applied it.
app.get("/deployment/:imei", (req, res) => {
  const imei = safeImei(req.params.imei);
  if (!imei) return res.status(400).json({ error: "Invalid IMEI" });
  const pending = stmts.getPendingDeployment.get(imei);
  const confirmed = stmts.getDeployed.get(imei);
  res.json({
    pending: pending ? {
      filename: pending.filename,
      state: JSON.parse(pending.state_json),
      status: pending.status,
      queuedAt: pending.queued_at,
      downloadedAt: pending.downloaded_at,
    } : null,
    confirmed: confirmed ? JSON.parse(confirmed.state_json) : null,
  });
});

app.post("/deployment/:imei", (req, res) => {
  const imei = safeImei(req.params.imei);
  if (!imei) return res.status(400).json({ error: "Invalid IMEI" });
  if (!stmts.configDevice.get(imei)?.configEnabled) {
    return res.status(409).json({ error: 'Device is not enabled for GL320MG configuration' });
  }
  const { content, state } = req.body;
  if (!content || typeof content !== "string") return res.status(400).json({ error: "content required" });
  if (!state || typeof state !== "object") return res.status(400).json({ error: "state required" });
  const filename = `${imei}.ini`;
  const fp = safeConfigPath(filename);
  if (!fs.existsSync(CONFIGS_DIR)) fs.mkdirSync(CONFIGS_DIR, { recursive: true });
  const queue = db.transaction(() => {
    fs.writeFileSync(fp, content, "utf8");
    stmts.upsertPendingDeployment.run(imei, filename, JSON.stringify(state));
  });
  queue();
  res.json({ ok: true, filename, status: "queued" });
});

// Templates
app.get('/templates', (req, res) => {
  res.json(stmts.allTemplates.all().map(r => r.name));
});

app.get('/template/:name', (req, res) => {
  const name = safeName(req.params.name);
  if (!name) return res.status(400).json({ error: 'Invalid name' });
  // Client sends underscores; convert to spaces for DB lookup
  const dbName = name.replace(/_/g, ' ');
  const row = stmts.getTemplate.get(dbName);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(JSON.parse(row.state_json));
});

app.post('/template/:name', (req, res) => {
  const name = safeName(req.params.name);
  if (!name) return res.status(400).json({ error: 'Invalid name' });
  const { state } = req.body;
  if (!state || typeof state !== 'object') return res.status(400).json({ error: 'state required' });
  const dbName = name.replace(/_/g, ' ');
  stmts.upsertTemplate.run(dbName, JSON.stringify(state));
  res.json({ ok: true });
});

app.delete('/template/:name', (req, res) => {
  const name = safeName(req.params.name);
  if (!name) return res.status(400).json({ error: 'Invalid name' });
  const dbName = name.replace(/_/g, ' ');
  stmts.deleteTemplate.run(dbName);
  res.json({ ok: true });
});

// Settings
app.get('/settings', (req, res) => {
  const rows = stmts.allSettings.all();
  const obj  = {};
  for (const r of rows) obj[r.key] = r.value;
  res.json(obj);
});

app.post('/settings', (req, res) => {
  const allowed = ['webhook_url', 'overdue_threshold_h', 'alert_enabled'];
  const updates = db.transaction(() => {
    for (const key of allowed) {
      if (key in req.body) stmts.setSetting.run(key, String(req.body[key]));
    }
  });
  updates();
  res.json({ ok: true });
});

// ── Config file management ────────────────────────────────────────────────────
app.get("/configs", (req, res) => {
  try {
    if (!fs.existsSync(CONFIGS_DIR)) return res.json([]);
    res.json(fs.readdirSync(CONFIGS_DIR).filter(f => /^[\w.\-]+$/.test(f)).sort());
  } catch { res.json([]); }
});

app.get("/config/:name", (req, res) => {
  const fp = safeConfigPath(req.params.name);
  if (!fp) return res.status(400).json({ error: "invalid filename" });
  try { res.type("text/plain").send(fs.readFileSync(fp, "utf8")); }
  catch { res.status(404).json({ error: "not found" }); }
});

app.post("/config/:name", (req, res) => {
  const fp = safeConfigPath(req.params.name);
  if (!fp) return res.status(400).json({ error: "invalid filename" });
  const imeiFilename = req.params.name.match(/^(\d{15})\.ini$/);
  if (imeiFilename && stmts.configDevice.get(imeiFilename[1])?.configEnabled === 0) {
    return res.status(409).json({ error: 'Device is not enabled for GL320MG configuration' });
  }
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "content required" });
  if (!fs.existsSync(CONFIGS_DIR)) fs.mkdirSync(CONFIGS_DIR, { recursive: true });
  fs.writeFileSync(fp, content, "utf8");
  res.json({ ok: true });
});

app.delete("/config/:name", (req, res) => {
  const filename = req.params.name;
  const fp = safeConfigPath(filename);
  if (!fp) return res.status(400).json({ error: "invalid filename" });
  if (!fs.existsSync(fp)) return res.status(404).json({ error: "not found" });
  try {
    fs.unlinkSync(fp);
    const imeiFilename = filename.match(/^(\d{15})\.ini$/);
    if (imeiFilename) stmts.deletePendingDeployment.run(imeiFilename[1], filename);
    res.json({ ok: true, filename });
  } catch (error) {
    res.status(500).json({ error: `delete failed: ${error.message}` });
  }
});

if (require.main === module) {
  app.listen(PORT, "127.0.0.1", () => {
    console.log(`Tracker API running on http://127.0.0.1:${PORT}`);
  });
}

module.exports = { app };
