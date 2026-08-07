(function (root, factory) {
  const api = factory();
  if (root) root.ConfigUtils = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const OFFICIAL_METADATA_PATTERNS = [
    /^Device Name:\s+GL320M(?:G)?$/i,
    /^Manage Tool Name:\s+Queclink_GL320M(?:G)?_Manage_Tool_[^\r\n]+?\s+Subversion:\s+Queclink_GL320M(?:G)?_Manage_Tool_[^\r\n]+$/i,
    /^Firmware Version:\s+GL320M(?:G)?_[\w.-]+$/i,
    /^Hardware Version:\s+GL320M(?:G)?_[\w.-]+$/i,
    /^Protocol Version:\s+[A-Z0-9._-]+$/i,
  ];

  function isOfficialMetadataLine(line) {
    return OFFICIAL_METADATA_PATTERNS.some(pattern => pattern.test(String(line || '').trim()));
  }

  function parseConfig(text) {
    const commands = {};
    const commandLines = [];
    const metadataLines = [];
    const otherLines = [];

    String(text || '').split(/\r?\n/).forEach((raw, index) => {
      const line = raw.trim();
      if (!line) return;
      const match = line.match(/^AT\+(GT[\w]+)=(.*?)\$\s*$/i);
      if (!match) {
        const target = isOfficialMetadataLine(line) ? metadataLines : otherLines;
        target.push({ line: raw, lineNumber: index + 1 });
        return;
      }
      const name = match[1].toUpperCase();
      const params = match[2].split(',');
      if (!commands[name]) commands[name] = [];
      commands[name].push(params);
      commandLines.push({ name, line: raw, lineNumber: index + 1, params });
    });

    return { commands, commandLines, metadataLines, otherLines };
  }

  function commandNames(text) {
    return new Set(parseConfig(text).commandLines.map(item => item.name));
  }

  function preservedLines(sourceText, generatedText) {
    const supported = commandNames(generatedText);
    const parsed = parseConfig(sourceText);
    return parsed.commandLines
      .filter(item => !supported.has(item.name))
      .map(item => item.line);
  }

  function unparsedLines(sourceText) {
    return parseConfig(sourceText).otherLines
      .map(item => item.line)
      .filter(line => line.trim());
  }

  function officialMetadataLines(sourceText) {
    return parseConfig(sourceText).metadataLines
      .map(item => item.line)
      .filter(line => line.trim());
  }

  function appendPreservedLines(generatedText, lines) {
    const base = String(generatedText || '').replace(/\s+$/, '');
    const extra = (lines || []).map(line => String(line).trim()).filter(Boolean);
    return `${base}${extra.length ? `\n${extra.join('\n')}` : ''}\n`;
  }

  function generatedLinesMissingFromSource(sourceText, generatedText) {
    const sourceCounts = {};
    parseConfig(sourceText).commandLines.forEach(item => {
      sourceCounts[item.name] = (sourceCounts[item.name] || 0) + 1;
    });
    return parseConfig(generatedText).commandLines.filter(item => {
      if ((sourceCounts[item.name] || 0) > 0) {
        sourceCounts[item.name]--;
        return false;
      }
      return true;
    });
  }

  // Keep the trusted baseline's command order. Supported commands are replaced
  // in place; unsupported commands remain byte-for-byte intact. Any generated
  // commands absent from the baseline are appended, and callers can use
  // generatedLinesMissingFromSource() to block that output when completeness is
  // required.
  function mergeWithSource(sourceText, generatedText) {
    const generated = parseConfig(generatedText);
    const queues = {};
    generated.commandLines.forEach(item => {
      if (!queues[item.name]) queues[item.name] = [];
      queues[item.name].push(item.line.trim());
    });

    const output = [];
    parseConfig(sourceText).commandLines.forEach(item => {
      const replacements = queues[item.name];
      output.push(replacements?.length ? replacements.shift() : item.line.trim());
    });
    Object.values(queues).forEach(lines => output.push(...lines));
    return `${output.join('\n')}\n`;
  }

  function configToMap(text) {
    const counters = {};
    const map = {};
    parseConfig(text).commandLines.forEach(item => {
      counters[item.name] = counters[item.name] || 0;
      map[`AT+${item.name}[${counters[item.name]++}]`] = item.line.trim();
    });
    return map;
  }

  function diffConfig(previous, next) {
    const oldMap = typeof previous === 'string' ? configToMap(previous) : (previous || {});
    const newMap = typeof next === 'string' ? configToMap(next) : (next || {});
    const keys = new Set([...Object.keys(oldMap), ...Object.keys(newMap)]);
    return [...keys].filter(key => oldMap[key] !== newMap[key]).map(key => ({
      key,
      old: oldMap[key] || null,
      new: newMap[key] || null,
    }));
  }

  function parseGtupcParams(params) {
    const values = Array.isArray(params) ? params : [];
    return {
      maxRetries: values[1] ?? '0',
      timeout: values[2] ?? '10',
      enableReport: values[4] ?? '0',
      interval: values[5] ?? '0',
      url: values[6] ?? '',
      mode: values[7] ?? '0',
    };
  }

  function buildGtupcCommand(password, settings, serialNumber = 'FFFF') {
    const values = settings || {};
    return `AT+GTUPC=${password},${values.maxRetries || '0'},${values.timeout || '10'},0,` +
      `${values.enableReport || '0'},${values.interval || '0'},${values.url || ''},` +
      `${values.mode || '0'},,,,${serialNumber}$`;
  }

  function toTrackerConfigText(text) {
    const normalized = String(text || '').replace(/\r\n?|\n/g, '\n').replace(/\n+$/, '');
    return normalized ? `${normalized.replace(/\n/g, '\r\n')}\r\n` : '';
  }

  return {
    appendPreservedLines,
    buildGtupcCommand,
    commandNames,
    configToMap,
    diffConfig,
    generatedLinesMissingFromSource,
    officialMetadataLines,
    mergeWithSource,
    parseConfig,
    parseGtupcParams,
    preservedLines,
    toTrackerConfigText,
    unparsedLines,
  };
});
