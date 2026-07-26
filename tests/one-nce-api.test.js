const test = require('node:test');
const assert = require('node:assert/strict');
const api = require('../api/oneNceApi');

const cfg = { user: 'u', pass: 'p', sourceAddress: '123456', sourceAddressTypeId: 145, dcs: 0 };

test('buildSmsBody produces the exact 1NCE envelope', () => {
  assert.deepEqual(api.buildSmsBody('AT+GTRTO=gl320m,1,,,,,,0001$', cfg), {
    source_address: '123456',
    payload: 'AT+GTRTO=gl320m,1,,,,,,0001$',
    dcs: 0,
    source_address_type: { id: 145 },
  });
});

test('validateAtCommand accepts a well-formed @Track command', () => {
  const r = api.validateAtCommand('  AT+GTRTO=gl320m,1,,,,,,0001$  ');
  assert.equal(r.ok, true);
  assert.equal(r.value, 'AT+GTRTO=gl320m,1,,,,,,0001$'); // trimmed
});

test('validateAtCommand rejects empty, non-AT, and unterminated commands', () => {
  assert.equal(api.validateAtCommand('').ok, false);
  assert.equal(api.validateAtCommand('DROP TABLE sims').ok, false);
  assert.equal(api.validateAtCommand('AT+GTRTO=gl320m,1').ok, false); // no $
  assert.equal(api.validateAtCommand('GTRTO=x$').ok, false);          // no AT+ prefix
  assert.equal(api.validateAtCommand('AT+GTRTO=' + 'x'.repeat(400) + '$').ok, false); // too long
});

test('getToken caches and only refetches when forced or expired', async () => {
  api._resetTokenCache();
  let calls = 0;
  const orig = globalThis.fetch;
  globalThis.fetch = async () => {
    calls++;
    return { ok: true, json: async () => ({ access_token: `tok${calls}`, expires_in: 600 }) };
  };
  try {
    const a = await api.getToken(cfg);
    const b = await api.getToken(cfg);           // cached — no new fetch
    assert.equal(a, 'tok1');
    assert.equal(b, 'tok1');
    assert.equal(calls, 1);
    const c = await api.getToken(cfg, { force: true }); // forced — new fetch
    assert.equal(c, 'tok2');
    assert.equal(calls, 2);
  } finally {
    globalThis.fetch = orig;
    api._resetTokenCache();
  }
});

test('getToken throws a clear error on a failed token request', async () => {
  api._resetTokenCache();
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 401, text: async () => 'bad creds' });
  try {
    await assert.rejects(() => api.getToken(cfg), /HTTP 401/);
  } finally {
    globalThis.fetch = orig;
    api._resetTokenCache();
  }
});
