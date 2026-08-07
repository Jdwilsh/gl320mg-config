const test = require('node:test');
const assert = require('node:assert/strict');
const { parseLogLine, isCompleteConfigDelivery } = require('../api/otaLog');

const imei = '860201067895410';
const trackerUa =
  `0408-${imei}-20260724170947-03-GL320M_B7K1-0108-81-c30c09-000000-92333f9618d594fee448e3d2ba7fb538`;

function line({ status = 206, bytes = 5983, ua = trackerUa, path = `/${imei}.ini` } = {}) {
  return `3.127.42.194 - - [24/Jul/2026:18:09:55 +0100] "GET ${path} HTTP/1.1" ${status} ${bytes} "-" "${ua}"`;
}

test('parses a GL320MG ranged config request with its actual request time and byte count', () => {
  assert.deepEqual(parseLogLine(line()), {
    imei,
    timestamp: '2026-07-24T17:09:47Z',
    requestedAt: '2026-07-24T17:09:55.000Z',
    ip: '3.127.42.194',
    config: `${imei}.ini`,
    status: 206,
    bytesSent: 5983,
  });
});

test('accepts a complete 206 tracker download but rejects partial, stale, wrong-path, and browser requests', () => {
  const stat = {
    size: 5983,
    mtimeMs: new Date('2026-07-23T23:19:52Z').getTime(),
  };
  assert.equal(isCompleteConfigDelivery(parseLogLine(line()), stat), true);
  assert.equal(isCompleteConfigDelivery(parseLogLine(line({ bytes: 2000 })), stat), false);
  assert.equal(isCompleteConfigDelivery(parseLogLine(line({ status: 200, bytes: 2000 })), stat), false);
  assert.equal(isCompleteConfigDelivery(parseLogLine(line({ status: 200, bytes: 5983 })), stat), true);
  assert.equal(isCompleteConfigDelivery(parseLogLine(line({ path: '/other.ini' })), stat), false);
  assert.equal(isCompleteConfigDelivery(parseLogLine(line()), {
    ...stat,
    mtimeMs: new Date('2026-07-24T18:10:00Z').getTime(),
  }), false);
  assert.equal(parseLogLine(line({ ua: 'curl/8.5.0', status: 200, bytes: 5983 })), null);
});
