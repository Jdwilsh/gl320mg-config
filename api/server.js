const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3010;
const LOG_FILE = "/var/log/nginx/cfg.access.log";
const DEVICES_FILE = path.join(__dirname, "..", "devices.json");

app.use(express.json());

// Allow the static frontend to call this API
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ── Log parsing ──────────────────────────────────────────────────────────────
// nginx combined log format:
//   IP - user [date] "METHOD path HTTP/x.x" STATUS bytes "ref" "UA"
// GL320MG user-agent format:
//   0408-{15-digit IMEI}-{14-digit timestamp YYYYMMDDHHmmss}-03-GL320M_...
const LOG_RE = /^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) \d+ "[^"]*" "([^"]*)"/;
const UA_RE  = /^(?:\d+)-(\d{15})-(\d{14})-.*GL320M/;

function parseLogLine(line) {
  const m = line.match(LOG_RE);
  if (!m) return null;
  const [, ip, , , reqPath, status, ua] = m;

  const uam = ua.match(UA_RE);
  if (!uam) return null;

  const imei = uam[1];
  const ts   = uam[2]; // YYYYMMDDHHmmss
  const isoTs = `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}T` +
                `${ts.slice(8,10)}:${ts.slice(10,12)}:${ts.slice(12,14)}Z`;

  return {
    imei,
    timestamp: isoTs,
    ip,
    config: reqPath.replace(/^\//, ""), // e.g. "1.GL320M"
    status: parseInt(status),
  };
}

// Simple cache — re-read log at most every 10 seconds
let logCache = null;
let logCacheTime = 0;

function readLog() {
  const now = Date.now();
  if (logCache && now - logCacheTime < 10000) return logCache;

  const trackers = {};

  try {
    const lines = fs.readFileSync(LOG_FILE, "utf8").split("\n");
    for (const line of lines) {
      if (!line) continue;
      const entry = parseLogLine(line);
      if (!entry) continue;

      if (!trackers[entry.imei]) {
        trackers[entry.imei] = {
          imei: entry.imei,
          lastSeen: entry.timestamp,
          lastIp: entry.ip,
          lastConfig: entry.config,
          lastStatus: entry.status,
          history: [],
        };
      }

      const t = trackers[entry.imei];

      // Keep the 20 most recent requests per tracker
      if (t.history.length < 20) {
        t.history.push(entry);
      }

      // Track the most recent event
      if (entry.timestamp >= t.lastSeen) {
        t.lastSeen    = entry.timestamp;
        t.lastIp      = entry.ip;
        t.lastConfig  = entry.config;
        t.lastStatus  = entry.status;
      }
    }
  } catch (err) {
    console.error("Error reading log:", err.message);
  }

  // Sort history newest-first per tracker
  for (const t of Object.values(trackers)) {
    t.history.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  }

  logCache = trackers;
  logCacheTime = now;
  return trackers;
}

// ── Device registry ───────────────────────────────────────────────────────────
function loadDevices() {
  try {
    if (fs.existsSync(DEVICES_FILE)) {
      return JSON.parse(fs.readFileSync(DEVICES_FILE, "utf8"));
    }
  } catch {}
  return {};
}

function saveDevices(devices) {
  fs.writeFileSync(DEVICES_FILE, JSON.stringify(devices, null, 2));
}

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /trackers — all tracker activity merged with device names
app.get("/trackers", (req, res) => {
  const trackers = readLog();
  const devices  = loadDevices();

  const result = Object.values(trackers).map(t => ({
    ...t,
    name: devices[t.imei] || null,
  }));

  result.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
  res.json(result);
});

// GET /devices — IMEI → name map
app.get("/devices", (req, res) => {
  res.json(loadDevices());
});

// POST /devices — set a name { imei, name }
app.post("/devices", (req, res) => {
  const { imei, name } = req.body;
  if (!imei) return res.status(400).json({ error: "imei required" });
  const devices = loadDevices();
  if (name && name.trim()) {
    devices[imei] = name.trim();
  } else {
    delete devices[imei];
  }
  saveDevices(devices);
  logCache = null; // invalidate cache so next /trackers picks up new names
  res.json({ ok: true });
});

// DELETE /devices/:imei — remove a name
app.delete("/devices/:imei", (req, res) => {
  const devices = loadDevices();
  delete devices[req.params.imei];
  saveDevices(devices);
  logCache = null;
  res.json({ ok: true });
});

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Tracker API running on http://127.0.0.1:${PORT}`);
});
