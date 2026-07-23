const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'gl320mg-api-'));
process.env.TRACKER_DB_PATH = path.join(testRoot, 'tracker.db');
process.env.TRACKER_CONFIGS_DIR = path.join(testRoot, 'configs');
process.env.TRACKER_LOG_FILE = path.join(testRoot, 'missing-access.log');
process.env.TRACKER_AUTH_FILE = path.join(testRoot, 'missing-auth.json');
process.env.DISABLE_LOG_WATCHER = '1';

const { app } = require('../api/server');

function startServer() {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}

test('queueing keeps pending state separate and writes a full IMEI config', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const imei = '860201067896228';
  const content = 'AT+GTSRI=gl320m,3,,1,example.test,5004,,,,,0001$\n';
  const state = { 'AT+GTSRI[0]': content.trim() };

  const queued = await fetch(`${base}/deployment/${imei}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ content, state }),
  });
  assert.equal(queued.status, 200);
  assert.deepEqual(await queued.json(), {
    ok: true,
    filename: `${imei}.ini`,
    status: 'queued',
  });

  const lifecycle = await fetch(`${base}/deployment/${imei}`);
  assert.equal(lifecycle.status, 200);
  const lifecycleBody = await lifecycle.json();
  assert.equal(lifecycleBody.confirmed, null);
  assert.equal(lifecycleBody.pending.filename, `${imei}.ini`);
  assert.deepEqual(lifecycleBody.pending.state, state);
  assert.equal(lifecycleBody.pending.status, 'queued');
  assert.match(lifecycleBody.pending.queuedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(lifecycleBody.pending.downloadedAt, null);

  assert.equal(
    fs.readFileSync(path.join(testRoot, 'configs', `${imei}.ini`), 'utf8'),
    content
  );
});

test('config listing exposes queued files to the workspace', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/configs`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), ['860201067896228.ini']);
});
