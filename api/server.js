const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = 3010;
const LOG_FILE      = "/var/log/nginx/cfg.access.log";
const DEVICES_FILE  = path.join(__dirname, "..", "devices.json");
const CONFIGS_DIR   = path.join(__dirname, "..", "configs");
const DEPLOYED_DIR  = path.join(__dirname, "..", "deployed");
const AUTH_FILE     = path.join(__dirname, "..", "auth.json");
const TEMPLATES_DIR = path.join(__dirname, '..', 'templates');

app.use(express.json());

// CORS
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

// Derive a stable token from the password hash — survives server restarts
function deriveToken(hash) {
  return crypto.createHmac("sha256", hash).update("tracker-session-v1").digest("hex");
}

// POST /login — unprotected
app.post("/login", (req, res) => {
  const hash = loadAuthHash();
  if (!hash) return res.json({ token: "dev", warning: "No password set" });
  const submitted = crypto.createHash("sha256")
    .update(req.body.password || "").digest("hex");
  if (submitted !== hash) return res.status(401).json({ error: "Incorrect password" });
  res.json({ token: deriveToken(hash) });
});

// Auth middleware — applied to all routes below
app.use((req, res, next) => {
  const hash = loadAuthHash();
  if (!hash) return next(); // no password configured — open access (dev)
  const bearer = (req.headers.authorization || "").replace(/^Bearer\s+/, "");
  if (bearer !== deriveToken(hash)) return res.status(401).json({ error: "Unauthorized" });
  next();
});

// ── Log parsing ──────────────────────────────────────────────────────────────
const LOG_RE = /^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) \d+ "[^"]*" "([^"]*)"/;
const UA_RE  = /^(?:\d+)-(\d{15})-(\d{14})-.*GL320M/;

function parseLogLine(line) {
  const m = line.match(LOG_RE);
  if (!m) return null;
  const [, ip, , , reqPath, status, ua] = m;
  const uam = ua.match(UA_RE);
  if (!uam) return null;
  const imei = uam[1];
  const ts   = uam[2];
  const isoTs = `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}T` +
                `${ts.slice(8,10)}:${ts.slice(10,12)}:${ts.slice(12,14)}Z`;
  return { imei, timestamp: isoTs, ip, config: reqPath.replace(/^\//, ""), status: parseInt(status) };
}

let logCache = null;
let logCacheTime = 0;

function readLog() {
  const now = Date.now();
  if (logCache && now - logCacheTime < 10000) return logCache;
  const trackers = {};
  // Read rotated files oldest-first so newer entries always win the lastSeen/lastStatus fields
  const files = [];
  for (let i = 5; i >= 1; i--) {
    const f = `${LOG_FILE}.${i}`;
    try { if (fs.existsSync(f)) files.push(f); } catch {}
  }
  files.push(LOG_FILE);
  for (const file of files) {
    try {
      const lines = fs.readFileSync(file, "utf8").split("\n");
      for (const line of lines) {
        if (!line) continue;
        const entry = parseLogLine(line);
        if (!entry) continue;
        if (!trackers[entry.imei]) {
          trackers[entry.imei] = {
            imei: entry.imei, lastSeen: entry.timestamp,
            lastIp: entry.ip, lastConfig: entry.config,
            lastStatus: entry.status, history: [],
          };
        }
        const t = trackers[entry.imei];
        if (t.history.length < 20) t.history.push(entry);
        if (entry.timestamp >= t.lastSeen) {
          t.lastSeen = entry.timestamp; t.lastIp = entry.ip;
          t.lastConfig = entry.config; t.lastStatus = entry.status;
        }
      }
    } catch (err) { console.error(`Error reading log ${file}:`, err.message); }
  }
  for (const t of Object.values(trackers))
    t.history.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  logCache = trackers;
  logCacheTime = now;
  return trackers;
}

// ── Device registry ───────────────────────────────────────────────────────────
function loadDevices() {
  try {
    if (fs.existsSync(DEVICES_FILE))
      return JSON.parse(fs.readFileSync(DEVICES_FILE, "utf8"));
  } catch {}
  return {};
}
function saveDevices(devices) {
  fs.writeFileSync(DEVICES_FILE, JSON.stringify(devices, null, 2));
}

// ── Deployed state ────────────────────────────────────────────────────────────
function safeImei(imei) { return /^\d{15}$/.test(imei) ? imei : null; }

function safeTemplatePath(name) {
  if (!/^[\w.\- ]+$/.test(name)) return null;
  const safe = name.replace(/\s+/g, '_');
  const resolved = path.resolve(TEMPLATES_DIR, safe + '.json');
  if (!resolved.startsWith(path.resolve(TEMPLATES_DIR) + path.sep)) return null;
  return resolved;
}

function loadDeployed(imei) {
  try {
    const fp = path.join(DEPLOYED_DIR, `${imei}.json`);
    if (fs.existsSync(fp)) return JSON.parse(fs.readFileSync(fp, "utf8"));
  } catch {}
  return null;
}

function saveDeployed(imei, state) {
  if (!fs.existsSync(DEPLOYED_DIR)) fs.mkdirSync(DEPLOYED_DIR, { recursive: true });
  fs.writeFileSync(path.join(DEPLOYED_DIR, `${imei}.json`), JSON.stringify(state));
}

// ── Auto-cleanup: delete .ini after confirmed delivery ────────────────────────
function cleanupDeliveredConfigs(trackers) {
  if (!fs.existsSync(CONFIGS_DIR)) return;
  let cleaned = false;
  for (const [imei, tracker] of Object.entries(trackers)) {
    const filename = `${imei}.ini`;
    const configPath = safeConfigPath(filename);
    if (!configPath || !fs.existsSync(configPath)) continue;
    let fileMtime;
    try { fileMtime = fs.statSync(configPath).mtimeMs; } catch { continue; }
    // Only delete if the tracker's most recent request was a successful download
    // of this specific file, AND that request happened after the file was written
    // (guards against stale log entries deleting a freshly deployed config)
    if (tracker.lastConfig === filename &&
        (tracker.lastStatus === 200 || tracker.lastStatus === 206) &&
        new Date(tracker.lastSeen).getTime() >= fileMtime) {
      try {
        fs.unlinkSync(configPath);
        console.log(`[cleanup] Deleted delivered config: ${filename}`);
        cleaned = true;
      } catch (e) {
        console.error(`[cleanup] Failed to delete ${filename}:`, e.message);
      }
    }
  }
  if (cleaned) logCache = null;
}

// ── Routes ────────────────────────────────────────────────────────────────────

app.get("/trackers", (req, res) => {
  const trackers = readLog();
  cleanupDeliveredConfigs(trackers);
  const devices  = loadDevices();
  const result = Object.values(trackers).map(t => ({
    ...t,
    name: devices[t.imei] || null,
    configPending: fs.existsSync(path.join(CONFIGS_DIR, `${t.imei}.ini`)),
  }));
  result.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
  res.json(result);
});

app.get("/devices", (req, res) => res.json(loadDevices()));

app.post("/devices", (req, res) => {
  const { imei, name } = req.body;
  if (!imei) return res.status(400).json({ error: "imei required" });
  const devices = loadDevices();
  if (name && name.trim()) devices[imei] = name.trim();
  else delete devices[imei];
  saveDevices(devices);
  logCache = null;
  res.json({ ok: true });
});

app.delete("/devices/:imei", (req, res) => {
  const devices = loadDevices();
  delete devices[req.params.imei];
  saveDevices(devices);
  logCache = null;
  res.json({ ok: true });
});

// GET /deployed/:imei — last deployed command map for a device
app.get("/deployed/:imei", (req, res) => {
  const imei = safeImei(req.params.imei);
  if (!imei) return res.status(400).json({ error: "Invalid IMEI" });
  res.json(loadDeployed(imei));
});

// POST /deployed/:imei — save new deployed state
app.post("/deployed/:imei", (req, res) => {
  const imei = safeImei(req.params.imei);
  if (!imei) return res.status(400).json({ error: "Invalid IMEI" });
  const { state } = req.body;
  if (!state || typeof state !== "object") return res.status(400).json({ error: "state required" });
  saveDeployed(imei, state);
  res.json({ ok: true });
});

// ── Templates ─────────────────────────────────────────────────────────────────
app.get('/templates', (req, res) => {
  try {
    if (!fs.existsSync(TEMPLATES_DIR)) return res.json([]);
    res.json(
      fs.readdirSync(TEMPLATES_DIR)
        .filter(f => f.endsWith('.json'))
        .map(f => f.replace(/_/g, ' ').replace(/\.json$/, ''))
        .sort()
    );
  } catch { res.json([]); }
});

app.get('/template/:name', (req, res) => {
  const fp = safeTemplatePath(req.params.name);
  if (!fp) return res.status(400).json({ error: 'Invalid name' });
  try { res.json(JSON.parse(fs.readFileSync(fp, 'utf8'))); }
  catch { res.status(404).json({ error: 'Not found' }); }
});

app.post('/template/:name', (req, res) => {
  const fp = safeTemplatePath(req.params.name);
  if (!fp) return res.status(400).json({ error: 'Invalid name' });
  const { state } = req.body;
  if (!state || typeof state !== 'object') return res.status(400).json({ error: 'state required' });
  if (!fs.existsSync(TEMPLATES_DIR)) fs.mkdirSync(TEMPLATES_DIR, { recursive: true });
  fs.writeFileSync(fp, JSON.stringify(state, null, 2));
  res.json({ ok: true });
});

app.delete('/template/:name', (req, res) => {
  const fp = safeTemplatePath(req.params.name);
  if (!fp) return res.status(400).json({ error: 'Invalid name' });
  try { fs.unlinkSync(fp); } catch {}
  res.json({ ok: true });
});

// ── Config file management ────────────────────────────────────────────────────
function safeConfigPath(name) {
  if (!/^[\w.\-]+$/.test(name)) return null;
  const resolved = path.resolve(CONFIGS_DIR, name);
  if (!resolved.startsWith(path.resolve(CONFIGS_DIR) + path.sep) &&
      resolved !== path.resolve(CONFIGS_DIR)) return null;
  return resolved;
}

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
