const fs   = require('fs');
const path = require('path');
const { db } = require('./db');
const { checkAndAlert } = require('./alerting');
const { parseLogLine, isCompleteConfigDelivery } = require('./otaLog');

const LOG_FILE = process.env.TRACKER_LOG_FILE || '/var/log/nginx/cfg.access.log';
const CONFIGS_DIR = process.env.TRACKER_CONFIGS_DIR || path.join(__dirname, '..', 'configs');
const POLL_MS  = 30_000;

const getCursor  = db.prepare('SELECT inode, byte_offset FROM log_cursor WHERE id = 1');
const saveCursor = db.prepare(
  'INSERT OR REPLACE INTO log_cursor (id, inode, byte_offset) VALUES (1, ?, ?)'
);
const insertEvent = db.prepare(
  'INSERT INTO tracker_events (imei, timestamp, ip, config, status) VALUES (?, ?, ?, ?, ?)'
);
const markDeploymentDownloaded = db.prepare(`
  UPDATE pending_deployments
  SET status = 'downloaded', downloaded_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
  WHERE imei = ? AND filename = ? AND status = 'queued'
`);
const getQueuedDeployment = db.prepare(`
  SELECT 1 FROM pending_deployments
  WHERE imei = ? AND filename = ? AND status = 'queued'
`);

function processLines(text) {
  // Returns array of parsed events from complete lines
  const lines  = text.split('\n');
  const events = [];
  // Last element may be a partial line — skip it (it has no trailing \n)
  for (let i = 0; i < lines.length - 1; i++) {
    const entry = parseLogLine(lines[i]);
    if (entry) events.push(entry);
  }
  return events;
}

function bytesOfCompleteLines(buf) {
  // Find how many bytes correspond to complete lines (ending with \n)
  const str = buf.toString('utf8');
  const last = str.lastIndexOf('\n');
  if (last === -1) return 0;
  return Buffer.byteLength(str.slice(0, last + 1), 'utf8');
}

function readChunk(filePath, fromOffset) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    const stat = fs.fstatSync(fd);
    if (fromOffset >= stat.size) return { text: '', consumed: 0, newOffset: fromOffset };
    const len = stat.size - fromOffset;
    const buf = Buffer.allocUnsafe(len);
    const bytesRead = fs.readSync(fd, buf, 0, len, fromOffset);
    const slice = buf.slice(0, bytesRead);
    const consumed = bytesOfCompleteLines(slice);
    const text = slice.slice(0, consumed).toString('utf8');
    return { text, consumed, newOffset: fromOffset + consumed };
  } catch (e) {
    console.error(`[watcher] readChunk(${filePath}, ${fromOffset}):`, e.message);
    return { text: '', consumed: 0, newOffset: fromOffset };
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
}

function insertEvents(events) {
  if (!events.length) return;
  const txn = db.transaction(() => {
    for (const e of events) insertEvent.run(e.imei, e.timestamp, e.ip, e.config, e.status);
  });
  txn();
}

function cleanupDeliveredConfigs(events) {
  for (const event of events) {
    const filename = `${event.imei}.ini`;
    if (!getQueuedDeployment.get(event.imei, filename)) continue;
    const configPath = path.join(CONFIGS_DIR, filename);
    let stat;
    try { stat = fs.statSync(configPath); } catch { continue; }
    if (!isCompleteConfigDelivery(event, stat)) continue;
    try {
      fs.unlinkSync(configPath);
      markDeploymentDownloaded.run(event.imei, filename);
      console.log(`[cleanup] Tracker downloaded complete config; deleted ${filename}`);
    } catch (error) {
      console.error(`[cleanup] Failed to complete ${filename}:`, error.message);
    }
  }
}

function reconcileQueuedDownloads() {
  const logFiles = [`${LOG_FILE}.1`, LOG_FILE];
  const events = [];
  for (const logFile of logFiles) {
    let text;
    try { text = fs.readFileSync(logFile, 'utf8'); } catch { continue; }
    events.push(...processLines(text.endsWith('\n') ? text : `${text}\n`));
  }
  cleanupDeliveredConfigs(events);
}

function poll() {
  try {
    let stat;
    try { stat = fs.statSync(LOG_FILE); }
    catch { return; } // log file doesn't exist yet

    const currentInode = stat.ino;
    const cursor = getCursor.get();

    if (!cursor) {
      // First ever run — seed cursor at end of file, no backfill
      saveCursor.run(currentInode, stat.size);
      console.log(`[watcher] first run — cursor seeded at byte ${stat.size}`);
      return;
    }

    const { inode: storedInode, byte_offset: storedOffset } = cursor;

    if (currentInode !== storedInode) {
      // Log was rotated — drain the old rotated file (.1) from storedOffset
      const rotated = `${LOG_FILE}.1`;
      if (fs.existsSync(rotated)) {
        const { text, newOffset } = readChunk(rotated, storedOffset);
        const events = processLines(text + '\n'); // ensure last line is treated as complete
        if (events.length) {
          insertEvents(events);
          cleanupDeliveredConfigs(events);
          console.log(`[watcher] drained rotated log: ${events.length} events`);
        }
      }
      // Reset cursor to start of new log file
      saveCursor.run(currentInode, 0);
      console.log('[watcher] log rotated — cursor reset');
      return;
    }

    if (stat.size < storedOffset) {
      // File was truncated
      saveCursor.run(currentInode, 0);
      console.log('[watcher] log truncated — cursor reset');
      return;
    }

    // Normal case — read from stored offset
    const { text, consumed, newOffset } = readChunk(LOG_FILE, storedOffset);
    if (!consumed) return;

    const events = processLines(text + '\n');
    if (events.length) {
      insertEvents(events);
      cleanupDeliveredConfigs(events);
      saveCursor.run(currentInode, newOffset);
      console.log(`[watcher] inserted ${events.length} events (offset ${storedOffset}→${newOffset})`);
    } else {
      saveCursor.run(currentInode, newOffset);
    }
  } catch (e) {
    console.error('[watcher] poll error:', e.message);
  }
}

function startLogWatcher() {
  // Recover completed downloads that occurred while the service was stopped or
  // before its cursor advanced. Only still-queued files can be removed.
  reconcileQueuedDownloads();
  poll(); // immediate first tick
  setInterval(() => {
    poll();
    checkAndAlert();
  }, POLL_MS);
  console.log('[watcher] started (30s interval)');
}

module.exports = { startLogWatcher };
