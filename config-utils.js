(function (root, factory) {
  const api = factory();
  if (root) root.ConfigUtils = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function parseConfig(text) {
    const commands = {};
    const commandLines = [];
    const otherLines = [];

    String(text || '').split(/\r?\n/).forEach((raw, index) => {
      const line = raw.trim();
      if (!line) return;
      const match = line.match(/^AT\+(GT[\w]+)=(.*?)\$\s*$/i);
      if (!match) {
        otherLines.push({ line: raw, lineNumber: index + 1 });
        return;
      }
      const name = match[1].toUpperCase();
      const params = match[2].split(',');
      if (!commands[name]) commands[name] = [];
      commands[name].push(params);
      commandLines.push({ name, line: raw, lineNumber: index + 1, params });
    });

    return { commands, commandLines, otherLines };
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

  return {
    appendPreservedLines,
    commandNames,
    configToMap,
    diffConfig,
    generatedLinesMissingFromSource,
    mergeWithSource,
    parseConfig,
    preservedLines,
    unparsedLines,
  };
});
