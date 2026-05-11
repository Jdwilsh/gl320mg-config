const Database = require('better-sqlite3');
const path     = require('path');

const DB_PATH = path.join(__dirname, 'tracker.db');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS tracker_events (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      imei      TEXT    NOT NULL,
      timestamp TEXT    NOT NULL,
      ip        TEXT    NOT NULL,
      config    TEXT    NOT NULL,
      status    INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_events_imei_ts
      ON tracker_events(imei, timestamp DESC);

    CREATE TABLE IF NOT EXISTS devices (
      imei TEXT PRIMARY KEY,
      name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS deployed_states (
      imei       TEXT PRIMARY KEY,
      state_json TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    CREATE TABLE IF NOT EXISTS templates (
      name       TEXT PRIMARY KEY,
      state_json TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    CREATE TABLE IF NOT EXISTS log_cursor (
      id          INTEGER PRIMARY KEY CHECK (id = 1),
      inode       INTEGER NOT NULL,
      byte_offset INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  const seed = db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`);
  seed.run('webhook_url',        '');
  seed.run('overdue_threshold_h', '48');
  seed.run('alert_enabled',      '0');

  console.log('[db] schema ready');
}

module.exports = { db, initSchema };
