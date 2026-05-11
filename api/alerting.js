const https = require('https');
const http  = require('http');
const { db } = require('./db');

let lastAlertSent = 0;
const COOLDOWN_MS = 60 * 60 * 1000; // 1 hour

function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function checkAndAlert() {
  try {
    if (getSetting('alert_enabled') !== '1') return;
    const webhookUrl = getSetting('webhook_url');
    if (!webhookUrl) return;

    const now = Date.now();
    if (now - lastAlertSent < COOLDOWN_MS) return;

    const thresholdH = parseFloat(getSetting('overdue_threshold_h') || '48');
    const cutoff = new Date(now - thresholdH * 3600 * 1000).toISOString();

    // Latest event per tracker via window function
    const overdue = db.prepare(`
      WITH ranked AS (
        SELECT e.imei, e.timestamp, e.ip,
               ROW_NUMBER() OVER (PARTITION BY e.imei ORDER BY e.timestamp DESC) AS rn
        FROM tracker_events e
      )
      SELECT r.imei, r.timestamp AS lastSeen, r.ip AS lastIp,
             d.name
      FROM ranked r
      LEFT JOIN devices d ON d.imei = r.imei
      WHERE r.rn = 1
        AND r.timestamp < ?
    `).all(cutoff);

    if (!overdue.length) return;

    lastAlertSent = now;

    const payload = JSON.stringify({
      event:         'trackers_overdue',
      timestamp:     new Date(now).toISOString(),
      overdue_count: overdue.length,
      trackers:      overdue.map(t => ({
        imei:     t.imei,
        name:     t.name || null,
        lastSeen: t.lastSeen,
        lastIp:   t.lastIp,
      })),
    });

    let url;
    try { url = new URL(webhookUrl); }
    catch { console.error('[alert] invalid webhook_url:', webhookUrl); return; }

    const options = {
      hostname: url.hostname,
      port:     url.port || (url.protocol === 'https:' ? 443 : 80),
      path:     url.pathname + url.search,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    };

    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request(options, res => {
      console.log(`[alert] webhook POST → ${res.statusCode} (${overdue.length} overdue trackers)`);
    });
    req.on('error', e => console.error('[alert] webhook error:', e.message));
    req.write(payload);
    req.end();
  } catch (e) {
    console.error('[alert] checkAndAlert error:', e.message);
  }
}

module.exports = { checkAndAlert };
