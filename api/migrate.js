const fs   = require('fs');
const path = require('path');

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
  return { imei, timestamp: isoTs, ip,
           config: reqPath.replace(/^\//, ''), status: parseInt(status) };
}

function runMigration(db, { DEVICES_FILE, DEPLOYED_DIR, TEMPLATES_DIR, LOG_FILE }) {
  const migrate = db.transaction(() => {
    // 1. devices.json → devices table (only if table is empty)
    const deviceCount = db.prepare('SELECT COUNT(*) AS n FROM devices').get().n;
    if (deviceCount === 0 && fs.existsSync(DEVICES_FILE)) {
      try {
        const devices = JSON.parse(fs.readFileSync(DEVICES_FILE, 'utf8'));
        const ins = db.prepare('INSERT OR IGNORE INTO devices (imei, name) VALUES (?, ?)');
        let n = 0;
        for (const [imei, name] of Object.entries(devices)) {
          if (imei && name) { ins.run(imei, name); n++; }
        }
        if (n) console.log(`[migrate] devices: imported ${n} entries`);
      } catch (e) {
        console.error('[migrate] devices.json read error:', e.message);
      }
    }

    // 2. deployed/<IMEI>.json → deployed_states (skip existing)
    if (fs.existsSync(DEPLOYED_DIR)) {
      const ins = db.prepare(
        'INSERT OR IGNORE INTO deployed_states (imei, state_json) VALUES (?, ?)'
      );
      let n = 0;
      try {
        for (const file of fs.readdirSync(DEPLOYED_DIR)) {
          const m = file.match(/^(\d{15})\.json$/);
          if (!m) continue;
          const imei = m[1];
          try {
            const state = fs.readFileSync(path.join(DEPLOYED_DIR, file), 'utf8');
            JSON.parse(state); // validate
            ins.run(imei, state);
            n++;
          } catch (e) {
            console.error(`[migrate] deployed/${file} error:`, e.message);
          }
        }
        if (n) console.log(`[migrate] deployed_states: imported ${n} entries`);
      } catch (e) {
        console.error('[migrate] deployed dir read error:', e.message);
      }
    }

    // 3. templates/*.json → templates (underscore filenames → space names, skip existing)
    if (fs.existsSync(TEMPLATES_DIR)) {
      const ins = db.prepare(
        'INSERT OR IGNORE INTO templates (name, state_json) VALUES (?, ?)'
      );
      let n = 0;
      try {
        for (const file of fs.readdirSync(TEMPLATES_DIR)) {
          if (!file.endsWith('.json')) continue;
          const name = file.replace(/_/g, ' ').replace(/\.json$/, '');
          try {
            const state = fs.readFileSync(path.join(TEMPLATES_DIR, file), 'utf8');
            JSON.parse(state); // validate
            ins.run(name, state);
            n++;
          } catch (e) {
            console.error(`[migrate] templates/${file} error:`, e.message);
          }
        }
        if (n) console.log(`[migrate] templates: imported ${n} entries`);
      } catch (e) {
        console.error('[migrate] templates dir read error:', e.message);
      }
    }

    // 4. Backfill tracker_events from nginx logs if table is empty
    //    Also clears any stale cursor so the log watcher reseeds at current position.
    const eventCount = db.prepare('SELECT COUNT(*) AS n FROM tracker_events').get().n;
    if (eventCount === 0 && LOG_FILE) {
      db.prepare('DELETE FROM log_cursor').run();
      const ins = db.prepare(
        'INSERT INTO tracker_events (imei, timestamp, ip, config, status) VALUES (?, ?, ?, ?, ?)'
      );
      // Read rotated files oldest-first, then current log
      const files = [];
      for (let i = 5; i >= 1; i--) {
        const f = `${LOG_FILE}.${i}`;
        try { if (fs.existsSync(f)) files.push(f); } catch {}
      }
      files.push(LOG_FILE);
      let total = 0;
      for (const file of files) {
        try {
          const lines = fs.readFileSync(file, 'utf8').split('\n');
          for (const line of lines) {
            if (!line) continue;
            const entry = parseLogLine(line);
            if (entry) { ins.run(entry.imei, entry.timestamp, entry.ip, entry.config, entry.status); total++; }
          }
        } catch (e) {
          console.error(`[migrate] log backfill ${file}:`, e.message);
        }
      }
      if (total) console.log(`[migrate] log backfill: inserted ${total} events`);
    }
  });

  try {
    migrate();
    console.log('[migrate] done');
  } catch (e) {
    console.error('[migrate] transaction error:', e.message);
  }
}

module.exports = { runMigration };
