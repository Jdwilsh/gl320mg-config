const fs   = require('fs');
const { db } = require('./db');
const { checkAndAlert } = require('./alerting');

const LOG_FILE = '/var/log/nginx/cfg.access.log';
const POLL_MS  = 30_000;

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

const getCursor  = db.prepare('SELECT inode, byte_offset FROM log_cursor WHERE id = 1');
const saveCursor = db.prepare(
  'INSERT OR REPLACE INTO log_cursor (id, inode, byte_offset) VALUES (1, ?, ?)'
);
const insertEvent = db.prepare(
  'INSERT INTO tracker_events (imei, timestamp, ip, config, status) VALUES (?, ?, ?, ?, ?)'
);

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
  poll(); // immediate first tick
  setInterval(() => {
    poll();
    checkAndAlert();
  }, POLL_MS);
  console.log('[watcher] started (30s interval)');
}

module.exports = { startLogWatcher };
