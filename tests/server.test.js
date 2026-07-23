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
process.env.TRACKER_DEVICES_FILE = path.join(testRoot, 'missing-devices.json');
process.env.TRACKER_DEPLOYED_DIR = path.join(testRoot, 'missing-deployed');
process.env.TRACKER_TEMPLATES_DIR = path.join(testRoot, 'missing-templates');
process.env.DISABLE_LOG_WATCHER = '1';
process.env.ONE_NCE_BASIC_AUTH = Buffer.from('streamer:very-secret').toString('base64');

const { app } = require('../api/server');
const { normalizeRecord, canonicalImei } = require('../api/oneNce');

function startServer() {
  return new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}

test('IMEI-SV values are converted back to the canonical 15-digit IMEI', () => {
  // FMM920 examples: the portal replaces the check digit with software version 03.
  assert.equal(canonicalImei('8682060840143703'), '868206084014376');
  assert.equal(canonicalImei('8608130709248503'), '860813070924852');
  assert.equal(canonicalImei('8682060840021703'), '868206084002173');

  // GL320MG examples: the same base IMEI is followed by software version 33.
  assert.equal(canonicalImei('8602010679010633'), '860201067901069');
  assert.equal(canonicalImei('8602010678962233'), '860201067896228');
  assert.equal(canonicalImei('8602010678951533'), '860201067895154');

  assert.equal(canonicalImei('860201067899156'), '860201067899156');
});

test('1NCE normalizer understands Platform 2.0 flat usage and event fields', () => {
  const usage = normalizeRecord({
    id: 9001,
    ingestion_timestamp: '2026-07-23T17:00:00Z',
    start_timestamp: '2026-07-23T16:45:00Z',
    end_timestamp: '2026-07-23T17:00:00Z',
    endpoint_imei: '860201067896228',
    endpoint_ip_address: '10.2.3.4',
    operator_id: 81,
    operator_country_id: 44,
    operator_mnc: '20',
    traffic_type_id: 5,
    rat_type: 9,
    volume_total: 2.5,
    volume_tx: 0.5,
    volume_rx: 2,
    cost: 0,
  });
  assert.equal(usage.recordKind, 'usage');
  assert.equal(usage.trafficType, 'Data');
  assert.equal(usage.ratType, 'LTE-M');
  assert.equal(usage.operatorName, 'Operator #81');
  assert.equal(usage.countryName, 'Country #44');
  assert.equal(usage.volumeTotal, 2.5);
  assert.equal(usage.currencyCode, 'EUR');

  const event = normalizeRecord({
    id: 9002,
    timestamp: '2026-07-23T17:01:00Z',
    endpoint_imei: '860201067896228',
    event_type_id: 3,
    event_severity_id: 2,
    detail_pdp_context_apn: 'iot.1nce.net',
    detail_pdp_context_rat_type: 8,
    detail_volume_total: 1.25,
  });
  assert.equal(event.recordKind, 'event');
  assert.equal(event.eventType, 'Create PDP Context');
  assert.equal(event.eventSeverity, 'Critical');
  assert.equal(event.apn, 'iot.1nce.net');
  assert.equal(event.ratType, 'NB-IoT');
  assert.equal(event.volumeTotal, 1.25);
});

test('1NCE normalizer understands nested Data Streamer event records', () => {
  const event = normalizeRecord({
    alert: false,
    description: 'New PDP Context successfully activated with SGSN CP=149.254.208.113, DP=149.254.208.116.',
    detail: {
      country: {
        country_code: '44',
        id: 205,
        iso_code: 'gb',
        mcc: '234',
        name: 'United Kingdom',
      },
      id: 10,
      name: 'EE',
      pdp_context: {
        apn: 'sensor.net',
        ci: 7342,
        imeisv: '8602010679010633',
        imsi: '901405180005433',
        ipcan_session_id: '8ec7b8d0-bf49-4d56-ad59-3b4e0fa59795',
        lac: 2639,
        mcc: '234',
        mnc: '30',
        rac: 255,
        rat_type: 2,
        ue_ip_address: '10.0.0.1',
      },
    },
    endpoint: {
      id: 100033927,
      imei: '8602010679010633',
      ip_address: '10.0.0.1',
      name: '8988228066680005433',
    },
    event_severity: { description: 'INFO', id: 0 },
    event_source: { description: 'Network', id: 0 },
    event_type: { description: 'Create PDP Context', id: 3 },
    id: 357945502,
    imsi: { id: 100034892, imsi: '901405180005433' },
    sim: {
      iccid: '8988228066680005433',
      id: 10034892,
      msisdn: '882285110127502',
    },
    timestamp: '2026-07-23T21:25:40.301Z',
  });

  assert.equal(event.recordKind, 'event');
  assert.equal(event.sourceRecordId, '357945502');
  assert.equal(event.imei, '860201067901069');
  assert.equal(event.imsi, '901405180005433');
  assert.equal(event.iccid, '8988228066680005433');
  assert.equal(event.eventType, 'Create PDP Context');
  assert.equal(event.eventSeverity, 'INFO');
  assert.equal(event.operatorName, 'EE');
  assert.equal(event.operatorMnc, '30');
  assert.equal(event.countryName, 'United Kingdom');
  assert.equal(event.countryMcc, '234');
  assert.equal(event.endpointIp, '10.0.0.1');
  assert.equal(event.apn, 'sensor.net');
  assert.equal(event.ratType, '2G');
});

test('SIM activity returns numeric zero totals before the first delivery', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/sim-activity`);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.receiver.callbackUrl, 'https://1nce.jdwilsh.com/api/1nce/data-streamer');
  assert.deepEqual(body.summary, {
    totalRecords: 0,
    simsSeen: 0,
    records24h: 0,
    volume24h: 0,
    alerts24h: 0,
    lastReceivedAt: null,
  });
});

test('queueing keeps pending state separate and writes a full IMEI config', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const imei = '860201067896228';
  const content = 'AT+GTSRI=gl320m,3,,1,example.test,5004,,,,,0001$\n';
  const state = { 'AT+GTSRI[0]': content.trim() };

  const registered = await fetch(`${base}/devices`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ imei, name: 'GL320MG test', deviceType: 'GL320MG' }),
  });
  assert.equal(registered.status, 200);

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

test('deleting a queued config also cancels its pending deployment', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const imei = '860201067896228';

  const removed = await fetch(`${base}/config/${imei}.ini`, { method: 'DELETE' });
  assert.equal(removed.status, 200);
  assert.deepEqual(await removed.json(), { ok: true, filename: `${imei}.ini` });
  assert.equal(fs.existsSync(path.join(testRoot, 'configs', `${imei}.ini`)), false);

  const lifecycle = await fetch(`${base}/deployment/${imei}`);
  assert.equal(lifecycle.status, 200);
  assert.equal((await lifecycle.json()).pending, null);
});

test('monitoring-only devices keep names but cannot receive GL320MG configs', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const imei = '350612345678901';

  const registered = await fetch(`${base}/devices`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ imei, name: 'FMM920 Van 4', deviceType: 'FMM920' }),
  });
  assert.equal(registered.status, 200);

  const names = await (await fetch(`${base}/devices`)).json();
  assert.equal(names[imei], 'FMM920 Van 4');

  const details = await (await fetch(`${base}/device-details`)).json();
  const fmm = details.find(device => device.imei === imei);
  assert.deepEqual(fmm, {
    imei,
    name: 'FMM920 Van 4',
    deviceType: 'FMM920',
    configEnabled: false,
  });

  const deployment = await fetch(`${base}/deployment/${imei}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ content: 'AT+GTCFG=gl320m,1$', state: { GTCFG: 'test' } }),
  });
  assert.equal(deployment.status, 409);
  assert.match((await deployment.json()).error, /not enabled/);
  assert.equal(fs.existsSync(path.join(testRoot, 'configs', `${imei}.ini`)), false);

  const draft = await fetch(`${base}/config/${imei}.ini`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ content: 'AT+GTCFG=gl320m,1$' }),
  });
  assert.equal(draft.status, 409);
});

test('tracker activity includes registered GL320MG devices before their first request', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const imei = '860201067895410';

  const registered = await fetch(`${base}/devices`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ imei, name: 'TRK06', deviceType: 'GL320MG' }),
  });
  assert.equal(registered.status, 200);

  const trackers = await (await fetch(`${base}/trackers`)).json();
  const tracker = trackers.find(item => item.imei === imei);
  assert.ok(tracker);
  assert.equal(tracker.name, 'TRK06');
  assert.equal(tracker.lastSeen, null);
  assert.equal(tracker.lastConfig, null);
  assert.equal(tracker.lastStatus, null);
  assert.deepEqual(tracker.history, []);
});

test('1NCE receiver authenticates bulk records, deduplicates retries, and joins device names', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const receiver = `${base}/1nce/data-streamer`;
  const authorization = `Basic ${process.env.ONE_NCE_BASIC_AUTH}`;

  const unauthorized = await fetch(receiver, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '[]',
  });
  assert.equal(unauthorized.status, 401);

  const invalidShape = await fetch(receiver, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization },
    body: JSON.stringify([42]),
  });
  assert.equal(invalidShape.status, 400);

  const usage = {
    id: 'usage-1001',
    start_timestamp: '2026-07-23T10:00:00Z',
    end_timestamp: '2026-07-23T10:15:00Z',
    cost: 0.0042,
    currency: { code: 'EUR', symbol: '€' },
    volume: { total: 1536, tx: 512, rx: 1024 },
    imsi: '901405101234567',
    sim: {
      iccid: '8988280666000000001',
      msisdn: '882350123456789',
    },
    traffic_type: { id: 5, description: 'Data' },
    operator: {
      id: 42,
      mnc: '10',
      name: 'Example Mobile',
      country: { mcc: '234', name: 'United Kingdom' },
    },
    endpoint: {
      id: 99,
      imei: '8602010678962233',
      ip_address: '10.1.2.3',
      name: 'Tracker endpoint',
      tags: ['gl320mg'],
    },
  };
  const event = {
    id: 'event-2001',
    timestamp: '2026-07-23T10:16:00Z',
    description: 'Create PDP Context',
    alert: true,
    event_source: { id: 1, description: 'Network' },
    event_severity: { id: 1, description: 'Info' },
    event_type: { id: 77, description: 'Create PDP Context' },
    imsi: { id: 5, imsi: '901405101234567' },
    sim: { id: 10, iccid: '8988280666000000001', msisdn: '882350123456789' },
    endpoint: { id: 99, imei: '8602010678962233', ip_address: '10.1.2.3' },
    detail: {
      pdp_context: {
        apn: 'iot.1nce.net',
        rat_type: 'LTE-M',
        ue_ip_address: '10.1.2.3',
        mcc: '234',
        mnc: '10',
      },
    },
  };

  const accepted = await fetch(receiver, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization },
    body: JSON.stringify([usage, event]),
  });
  assert.equal(accepted.status, 200);
  assert.deepEqual(await accepted.json(), {
    ok: true,
    received: 2,
    inserted: 2,
    duplicates: 0,
  });

  const retried = await fetch(receiver, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization },
    body: JSON.stringify([usage, event]),
  });
  assert.equal(retried.status, 200);
  assert.deepEqual(await retried.json(), {
    ok: true,
    received: 2,
    inserted: 0,
    duplicates: 2,
  });

  const named = await fetch(`${base}/devices`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ imei: '860201067896228', name: 'Medical Bag 12' }),
  });
  assert.equal(named.status, 200);

  const activity = await fetch(`${base}/sim-activity`);
  assert.equal(activity.status, 200);
  const body = await activity.json();
  assert.equal(body.summary.totalRecords, 2);
  assert.equal(body.summary.simsSeen, 1);
  assert.equal(body.summary.alerts24h, 1);
  assert.equal(body.receiver.configured, true);
  assert.equal(body.records.length, 2);
  assert.equal(body.records[0].recordKind, 'event');
  assert.equal(body.records[0].deviceName, 'Medical Bag 12');
  assert.equal(body.records[0].apn, 'iot.1nce.net');
  assert.equal(body.records[0].ratType, 'LTE-M');
  assert.equal(body.records[0].volumeTotal, null);
  assert.equal(body.records[0].cost, null);
  assert.equal(body.records[1].recordKind, 'usage');
  assert.equal(body.records[1].volumeTotal, 1536);
  assert.equal(body.records[1].operatorName, 'Example Mobile');

  const detail = await fetch(`${base}/sim-activity/${body.records[1].id}`);
  assert.equal(detail.status, 200);
  const detailBody = await detail.json();
  assert.deepEqual(detailBody.raw.endpoint.tags, ['gl320mg']);
});

test('1NCE receiver stores MO SMS and MT delivery reports and resolves ICCID to IMEI', async t => {
  const server = await startServer();
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;
  const receiver = `${base}/1nce/data-streamer`;
  const authorization = `Basic ${process.env.ONE_NCE_BASIC_AUTH}`;
  const imei = '860201067896228';
  const iccid = '8988280666000000001';

  await fetch(`${base}/devices`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ imei, name: 'Medical Bag 12' }),
  });
  const mobileOriginated = {
    id: 6202,
    payload: 'Tracker status OK',
    submit_date: '2026-07-23 16:31:51',
    destination_address: '12345',
    source_address: '882350123456789',
    dcs: 0,
    endpoint: { id: 1234567, name: iccid },
    organisation: { id: 1234 },
    multi_part_info: { partno: 1, total: 1, identifier: 6202 },
    pid: 0,
  };
  const moResponse = await fetch(receiver, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization },
    body: JSON.stringify(mobileOriginated),
  });
  assert.equal(moResponse.status, 200);
  assert.equal((await moResponse.json()).inserted, 1);

  const deliveryReport = {
    id: 2819195,
    final_date: '2026-07-23 16:32:38',
    submit_date: '2026-07-23 16:32:34',
    organisation: { id: 1234 },
    endpoint: { name: iccid, id: 1234567 },
    status: { id: 4, status: 'DELIVERED' },
  };
  const mtResponse = await fetch(receiver, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', authorization },
    body: JSON.stringify(deliveryReport),
  });
  assert.equal(mtResponse.status, 200);
  assert.equal((await mtResponse.json()).inserted, 1);

  // The SMS forwarder only identifies endpoint.name as the ICCID. A later
  // usage/event record carrying both ICCID and IMEI must backfill the join.
  await fetch(receiver, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization },
    body: JSON.stringify([{
      id: 'sms-link-record',
      end_timestamp: '2026-07-23T16:33:00Z',
      volume: { total: 1, tx: 1, rx: 0 },
      traffic_type: { id: 5, description: 'Data' },
      sim: { iccid },
      endpoint: { imei },
    }]),
  });

  const activity = await fetch(`${base}/sim-activity?kind=sms_mt`);
  assert.equal(activity.status, 200);
  const body = await activity.json();
  assert.equal(body.records.length, 1);
  assert.equal(body.records[0].recordKind, 'sms_mt');
  assert.equal(body.records[0].smsStatus, 'DELIVERED');
  assert.equal(body.records[0].iccid, iccid);
  assert.equal(body.records[0].imei, imei);
  assert.equal(body.records[0].deviceName, 'Medical Bag 12');

  const moActivity = await fetch(`${base}/sim-activity?kind=sms_mo`);
  const moBody = await moActivity.json();
  assert.equal(moBody.records[0].smsPayload, 'Tracker status OK');
  assert.equal(moBody.records[0].smsPartNumber, 1);
  assert.equal(moBody.records[0].smsTotalParts, 1);
});
