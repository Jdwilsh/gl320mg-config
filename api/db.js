const Database = require('better-sqlite3');
const path     = require('path');

const DB_PATH = process.env.TRACKER_DB_PATH || path.join(__dirname, 'tracker.db');
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
      imei           TEXT PRIMARY KEY,
      name           TEXT NOT NULL,
      device_type    TEXT NOT NULL DEFAULT 'GL320MG',
      config_enabled INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS sim_activity (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      source_record_id TEXT,
      record_kind      TEXT NOT NULL,
      received_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      event_timestamp  TEXT,
      start_timestamp  TEXT,
      end_timestamp    TEXT,
      imei             TEXT,
      imsi             TEXT,
      iccid            TEXT,
      msisdn           TEXT,
      traffic_type     TEXT,
      event_type       TEXT,
      event_severity   TEXT,
      is_alert         INTEGER NOT NULL DEFAULT 0,
      description      TEXT,
      operator_name    TEXT,
      operator_mnc     TEXT,
      country_name     TEXT,
      country_mcc      TEXT,
      endpoint_ip      TEXT,
      apn              TEXT,
      rat_type         TEXT,
      volume_total     REAL,
      volume_tx        REAL,
      volume_rx        REAL,
      cost             REAL,
      currency_code    TEXT,
      sms_status       TEXT,
      sms_payload      TEXT,
      sms_source       TEXT,
      sms_destination  TEXT,
      sms_dcs          TEXT,
      sms_part_number  INTEGER,
      sms_total_parts  INTEGER,
      raw_json         TEXT NOT NULL,
      dedupe_key       TEXT NOT NULL UNIQUE
    );
    CREATE INDEX IF NOT EXISTS idx_sim_activity_imei_ts
      ON sim_activity(imei, event_timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_sim_activity_received
      ON sim_activity(received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sim_activity_imsi
      ON sim_activity(imsi);
    CREATE INDEX IF NOT EXISTS idx_sim_activity_iccid
      ON sim_activity(iccid);

    CREATE TABLE IF NOT EXISTS deployed_states (
      imei       TEXT PRIMARY KEY,
      state_json TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    CREATE TABLE IF NOT EXISTS pending_deployments (
      imei          TEXT PRIMARY KEY,
      filename      TEXT NOT NULL,
      state_json    TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'queued',
      queued_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      downloaded_at TEXT
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

    -- SMS commands sent to trackers via the 1NCE Management API. One row per
    -- (command, tracker) so a fan-out to several trackers records each result.
    CREATE TABLE IF NOT EXISTS sms_commands (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      iccid      TEXT,
      imei       TEXT,
      device_name TEXT,
      payload    TEXT NOT NULL,
      status     TEXT NOT NULL DEFAULT 'sent',   -- sent | failed
      http_status INTEGER,
      response   TEXT,
      sent_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_sms_commands_sent ON sms_commands(sent_at DESC);

    -- User-saved quick-command presets (name → AT payload). Seeded by the user
    -- from commands they have verified; never auto-populated with guesses.
    CREATE TABLE IF NOT EXISTS command_presets (
      name       TEXT PRIMARY KEY,
      payload    TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    -- Named configurations: build once, assign trackers, deploy to the group.
    -- state_json is the same workspace object a single tracker used to hold
    -- (form-field values); source_text is the trusted baseline .ini that carries
    -- unsupported commands verbatim. Deploying a config fans the generated .ini
    -- out to each member via the existing per-imei pending_deployments machinery.
    CREATE TABLE IF NOT EXISTS configs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL UNIQUE,
      state_json  TEXT NOT NULL DEFAULT '{}',
      source_text TEXT,
      created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );

    -- Membership: each tracker belongs to at most one config. A tracker with no
    -- row here is "unassigned". FK cascades so removing a config unassigns its
    -- members (their per-imei deployed state is untouched).
    CREATE TABLE IF NOT EXISTS config_members (
      imei        TEXT PRIMARY KEY,
      config_id   INTEGER NOT NULL REFERENCES configs(id) ON DELETE CASCADE,
      assigned_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_config_members_config ON config_members(config_id);
  `);

  // FK cascade only fires when foreign_keys is on (off by default in SQLite).
  db.pragma('foreign_keys = ON');

  // Additive upgrade for databases created before multiple tracker types were
  // supported. Existing entries remain GL320MG configuration targets.
  const deviceColumns = new Set(
    db.prepare('PRAGMA table_info(devices)').all().map(column => column.name)
  );
  if (!deviceColumns.has('device_type')) {
    db.exec("ALTER TABLE devices ADD COLUMN device_type TEXT NOT NULL DEFAULT 'GL320MG'");
  }
  if (!deviceColumns.has('config_enabled')) {
    db.exec('ALTER TABLE devices ADD COLUMN config_enabled INTEGER NOT NULL DEFAULT 1');
  }

  const seed = db.prepare(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`);
  seed.run('webhook_url',        '');
  seed.run('overdue_threshold_h', '48');
  seed.run('alert_enabled',      '0');

  console.log('[db] schema ready');
}

module.exports = { db, initSchema };
