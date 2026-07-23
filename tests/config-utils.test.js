const test = require('node:test');
const assert = require('node:assert/strict');
const {
  appendPreservedLines,
  configToMap,
  diffConfig,
  parseConfig,
  preservedLines,
  unparsedLines,
} = require('../config-utils');

test('parseConfig retains repeated commands and non-command lines', () => {
  const parsed = parseConfig([
    'AT+GTAPN=gl320m,0,1,23430,internet,,,,,0001$',
    'AT+GTAPN=gl320m,1,0,,,,,,,0001$',
    '; operator note',
  ].join('\n'));

  assert.equal(parsed.commands.GTAPN.length, 2);
  assert.equal(parsed.commandLines.length, 2);
  assert.deepEqual(parsed.otherLines.map(item => item.line), ['; operator note']);
});

test('unsupported commands survive regeneration while non-command text is excluded', () => {
  const source = [
    'AT+GTSRI=gl320m,3,,1,example.com,5004,,,,,0001$',
    'AT+GTXYZ=gl320m,1,2,3,,,,0001$',
    '; keep this note',
  ].join('\n');
  const generated = 'AT+GTSRI=gl320m,3,,1,new.example.com,5004,,,,,0001$\n';
  const preserved = preservedLines(source, generated);

  assert.deepEqual(preserved, ['AT+GTXYZ=gl320m,1,2,3,,,,0001$']);
  assert.deepEqual(unparsedLines(source), ['; keep this note']);
  assert.match(appendPreservedLines(generated, preserved), /AT\+GTXYZ=/);
  assert.doesNotMatch(appendPreservedLines(generated, preserved), /keep this note/);
});

test('config maps provide stable keys for repeated commands', () => {
  const map = configToMap([
    'AT+GTAPN=gl320m,0,1,23430,internet,,,,,0001$',
    'AT+GTAPN=gl320m,1,0,,,,,,,0001$',
  ].join('\n'));

  assert.deepEqual(Object.keys(map), ['AT+GTAPN[0]', 'AT+GTAPN[1]']);
});

test('diffConfig reports additions, changes, and removals', () => {
  const previous = {
    'AT+GTAAA[0]': 'AT+GTAAA=old$',
    'AT+GTBBB[0]': 'AT+GTBBB=remove$',
  };
  const next = {
    'AT+GTAAA[0]': 'AT+GTAAA=new$',
    'AT+GTCCC[0]': 'AT+GTCCC=add$',
  };

  assert.deepEqual(diffConfig(previous, next), [
    { key: 'AT+GTAAA[0]', old: 'AT+GTAAA=old$', new: 'AT+GTAAA=new$' },
    { key: 'AT+GTBBB[0]', old: 'AT+GTBBB=remove$', new: null },
    { key: 'AT+GTCCC[0]', old: null, new: 'AT+GTCCC=add$' },
  ]);
});
