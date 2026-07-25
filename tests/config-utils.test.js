const test = require('node:test');
const assert = require('node:assert/strict');
const {
  appendPreservedLines,
  buildGtupcCommand,
  configToMap,
  diffConfig,
  generatedLinesMissingFromSource,
  mergeWithSource,
  officialMetadataLines,
  parseConfig,
  parseGtupcParams,
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

test('official Manage Tool headers are recognized without hiding unknown lines', () => {
  const source = [
    'Device Name: GL320M',
    'Manage Tool Name: Queclink_GL320M_Manage_Tool_V1.1.16  Subversion: Queclink_GL320M_Manage_Tool_V1.1.16',
    'Firmware Version: GL320M_R10A01V05',
    'Hardware Version: GL320M_HWR109',
    'Protocol Version: C30303',
    'AT+GTBSI=gl320m,sensor.net,,,,,,0,0,0,0,0,0,0,,FFFF$',
    '; unexpected text',
  ].join('\r\n');

  const parsed = parseConfig(source);
  assert.equal(parsed.commandLines.length, 1);
  assert.equal(parsed.metadataLines.length, 5);
  assert.equal(officialMetadataLines(source).length, 5);
  assert.deepEqual(unparsedLines(source), ['; unexpected text']);
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

test('trusted source order is retained while supported commands change in place', () => {
  const source = [
    'AT+GTXYZ=gl320m,keep,this,exactly$',
    'AT+GTSRI=gl320m,3,,1,old.example.com,5004,,,,,0001$',
    'AT+GTAPN=gl320m,0,1,23430,old-apn,,,,,0001$',
    'AT+GTAPN=gl320m,1,0,,,,,,,0001$',
  ].join('\n');
  const generated = [
    'AT+GTSRI=gl320m,3,,1,new.example.com,5004,,,,,0001$',
    'AT+GTAPN=gl320m,0,1,23430,new-apn,,,,,0001$',
    'AT+GTAPN=gl320m,1,0,,,,,,,0001$',
  ].join('\n');

  assert.equal(mergeWithSource(source, generated), [
    'AT+GTXYZ=gl320m,keep,this,exactly$',
    'AT+GTSRI=gl320m,3,,1,new.example.com,5004,,,,,0001$',
    'AT+GTAPN=gl320m,0,1,23430,new-apn,,,,,0001$',
    'AT+GTAPN=gl320m,1,0,,,,,,,0001$',
    '',
  ].join('\n'));
  assert.deepEqual(generatedLinesMissingFromSource(source, generated), []);
});

test('missing generated commands are detectable before deployment', () => {
  const source = 'AT+GTSRI=gl320m,3,,1,old.example.com,5004,,,,,0001$\n';
  const generated = [
    'AT+GTSRI=gl320m,3,,1,new.example.com,5004,,,,,0001$',
    'AT+GTCFG=gl320m,gl320m,tracker,,,,,,,,FFFF$',
  ].join('\n');

  assert.deepEqual(
    generatedLinesMissingFromSource(source, generated).map(item => item.name),
    ['GTCFG']
  );
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

test('an OTA interval edit is retained in place and reported as a GTUPC change', () => {
  const source = [
    'Device Name: GL320M',
    'AT+GTUPC=gl320m,1,10,0,1,24,http://cfg.jdwilsh.com/,1,,,,FFFF$',
  ].join('\r\n');
  const generated =
    'AT+GTUPC=gl320m,1,10,0,1,4,http://cfg.jdwilsh.com/,1,,,,FFFF$\n';
  const merged = mergeWithSource(source, generated);

  assert.equal(
    merged,
    'AT+GTUPC=gl320m,1,10,0,1,4,http://cfg.jdwilsh.com/,1,,,,FFFF$\n'
  );
  assert.deepEqual(diffConfig(source, merged), [{
    key: 'AT+GTUPC[0]',
    old: 'AT+GTUPC=gl320m,1,10,0,1,24,http://cfg.jdwilsh.com/,1,,,,FFFF$',
    new: 'AT+GTUPC=gl320m,1,10,0,1,4,http://cfg.jdwilsh.com/,1,,,,FFFF$',
  }]);
});

test('GTUPC fields follow the GL320M protocol order', () => {
  const command = buildGtupcCommand('gl320m', {
    maxRetries: '3',
    timeout: '10',
    enableReport: '1',
    interval: '6',
    url: 'http://cfg.jdwilsh.com/',
    mode: '1',
  });

  assert.equal(
    command,
    'AT+GTUPC=gl320m,3,10,0,1,6,http://cfg.jdwilsh.com/,1,,,,FFFF$'
  );

  const params = parseConfig(command).commands.GTUPC[0];
  assert.deepEqual(parseGtupcParams(params), {
    maxRetries: '3',
    timeout: '10',
    enableReport: '1',
    interval: '6',
    url: 'http://cfg.jdwilsh.com/',
    mode: '1',
  });
});
