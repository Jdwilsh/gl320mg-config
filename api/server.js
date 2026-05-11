const express = require("express");
const fs      = require("fs");
const path    = require("path");
const crypto  = require("crypto");

const { db, initSchema } = require('./db');
const { runMigration }   = require('./migrate');

const app  = express();
const PORT = 3010;

const DEVICES_FILE  = path.join(__dirname, "..", "devices.json");
const CONFIGS_DIR   = path.join(__dirname, "..", "configs");
const DEPLOYED_DIR  = path.join(__dirname, "..", "deployed");
const AUTH_FILE     = path.join(__dirname, "..", "auth.json");
const TEMPLATES_DIR = path.join(__dirname, '..', 'templates');

// ── Startup ───────────────────────────────────────────────────────────────────
initSchema();
runMigration(db, { DEVICES_FILE, DEPLOYED_DIR, TEMPLATES_DIR });

// logWatcher must be required AFTER initSchema (prepared statements need tables)
const { startLogWatcher } = require('./logWatcher');
startLogWatcher();

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
  upsertDevice: db.prepare('INSERT OR REPLACE INTO devices (imei, name) VALUES (?, ?)'),
  deleteDevice: db.prepare('DELETE FROM devices WHERE imei = ?'),

  // Deployed states
  getDeployed:    db.prepare('SELECT state_json FROM deployed_states WHERE imei = ?'),
  upsertDeployed: db.prepare(`
    INSERT OR REPLACE INTO deployed_states (imei, state_json, updated_at)
    VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
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
};

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
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
        (tracker.lastStatus === 200 || tracker.lastStatus === 206) &&
        new Date(tracker.lastSeen).getTime() >= fileMtime) {
      try {
        fs.unlinkSync(configPath);
        console.log(`[cleanup] Deleted delivered config: ${filename}`);
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
    return {
      imei:          t.imei,
      lastSeen:      t.lastSeen,
      lastIp:        t.lastIp,
      lastConfig:    t.lastConfig,
      lastStatus:    t.lastStatus,
      name:          t.name || null,
      configPending: fs.existsSync(path.join(CONFIGS_DIR, `${t.imei}.ini`)),
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

app.post("/devices", (req, res) => {
  const { imei, name } = req.body;
  if (!imei) return res.status(400).json({ error: "imei required" });
  if (name && name.trim()) {
    stmts.upsertDevice.run(imei, name.trim());
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
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "content required" });
  if (!fs.existsSync(CONFIGS_DIR)) fs.mkdirSync(CONFIGS_DIR, { recursive: true });
  fs.writeFileSync(fp, content, "utf8");
  res.json({ ok: true });
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Tracker API running on http://127.0.0.1:${PORT}`);
});
