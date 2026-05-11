const fs   = require('fs');
const path = require('path');

function runMigration(db, { DEVICES_FILE, DEPLOYED_DIR, TEMPLATES_DIR }) {
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
  });

  try {
    migrate();
    console.log('[migrate] done');
  } catch (e) {
    console.error('[migrate] transaction error:', e.message);
  }
}

module.exports = { runMigration };
