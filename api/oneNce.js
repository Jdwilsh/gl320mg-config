const crypto = require('crypto');

const TRAFFIC_TYPES = { 5: 'Data', 6: 'SMS' };
const EVENT_SEVERITIES = { 0: 'Info', 1: 'Warn', 2: 'Critical' };
const RAT_TYPES = {
  1: '3G', 2: '2G', 3: 'WLAN', 4: 'GAN', 5: 'HSPA+',
  6: '4G / LTE', 8: 'NB-IoT', 9: 'LTE-M', 10: '5G',
};
const EVENT_TYPES = {
  0: 'Generic', 1: 'Update location', 2: 'Update GPRS location',
  3: 'Create PDP Context', 4: 'Update PDP Context', 5: 'Delete PDP Context',
  6: 'User authentication failed', 7: 'Application authentication failed',
  8: 'SIM activation', 9: 'SIM suspension', 10: 'SIM deletion',
  11: 'Endpoint blocked', 12: 'Organization blocked', 13: 'Support Access',
  14: 'Multi-factor Authentication', 15: 'Purge Location', 16: 'Purge GPRS location',
  17: 'Self-Signup', 18: 'Data Quota Threshold reached', 19: 'Data Quota used up',
  20: 'SMS Quota Threshold reached', 21: 'SMS Quota used up',
  30: 'OpenVPN authentication', 50: 'SIM Released', 51: 'SIM Assigned',
  52: 'Data Quota Enabled', 53: 'Data Quota Disabled', 54: 'SMS Quota Enabled',
  55: 'SMS Quota Disabled', 56: 'Data Quota Assigned', 57: 'Data Quota Deleted',
  58: 'SMS Quota Assigned', 59: 'SMS Quota Deleted', 60: 'Data Quota expired',
};

function valueAt(source, paths) {
  for (const path of paths) {
    let value = source;
    for (const part of path.split('.')) value = value?.[part];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return null;
}

function scalar(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'object') {
    return value.description ?? value.name ?? value.code ?? value.id ?? null;
  }
  return value;
}

function text(value) {
  const result = scalar(value);
  return result === null ? null : String(result);
}

function number(value) {
  const source = scalar(value);
  if (source === null) return null;
  const result = Number(source);
  return Number.isFinite(result) ? result : null;
}

function timestamp(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value === 'number') {
    const date = new Date(value < 1e12 ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }
  const normalized = typeof value === 'string' && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value)
    ? `${value.replace(' ', 'T')}Z`
    : value;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
}

function findNested(source, keys) {
  if (!source || typeof source !== 'object') return null;
  for (const key of keys) {
    if (source[key] !== undefined && source[key] !== null && source[key] !== '') {
      return source[key];
    }
  }
  for (const value of Object.values(source)) {
    if (value && typeof value === 'object') {
      const found = findNested(value, keys);
      if (found !== null) return found;
    }
  }
  return null;
}

function inferKind(record) {
  if (record.payload !== undefined && (record.source_address || record.destination_address || record.dest_address)) {
    return 'sms_mo';
  }
  if (record.status && (record.final_date || record.submit_date)) return 'sms_mt';
  if (record.event_type || record.event_type_id !== undefined || record.event_source ||
      record.event_severity || record.alert !== undefined) {
    return 'event';
  }
  const traffic = (
    text(record.traffic_type) ?? TRAFFIC_TYPES[record.traffic_type_id] ?? ''
  ).toLowerCase();
  if (traffic.includes('sms')) return 'sms';
  if (record.volume || record.volume_total !== undefined || record.traffic_type_id !== undefined ||
      record.cost !== undefined || record.start_timestamp || record.end_timestamp) {
    return 'usage';
  }
  return 'record';
}

function normalizeRecord(record, kindHint = null) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new TypeError('Each 1NCE record must be a JSON object');
  }

  const rawJson = JSON.stringify(record);
  const kind = kindHint || inferKind(record);
  const sourceRecordId = text(valueAt(record, ['id', 'record_id', 'event_id']));
  const detail = record.detail && typeof record.detail === 'object' ? record.detail : {};
  const eventTimestamp = timestamp(valueAt(record, [
    'timestamp', 'event_timestamp', 'ingestion_timestamp', 'final_date', 'submit_date',
    'end_timestamp', 'start_timestamp', 'created_at',
  ]));
  const imei = text(valueAt(record, [
    'endpoint.imei', 'endpoint_imei', 'imei', 'device.imei', 'detail.endpoint.imei',
  ])) ?? text(findNested(detail, ['imei', 'imeisv']));
  const imsi = text(valueAt(record, [
    'imsi.imsi', 'imsi', 'sim.imsi', 'endpoint.imsi',
  ]));
  const dedupeKey = sourceRecordId
    ? crypto.createHash('sha256').update(`${kind}:${sourceRecordId}`).digest('hex')
    : crypto.createHash('sha256').update(rawJson).digest('hex');

  return {
    sourceRecordId,
    recordKind: kind,
    eventTimestamp,
    startTimestamp: timestamp(record.start_timestamp),
    endTimestamp: timestamp(record.end_timestamp),
    imei: imei?.match(/\d{15}/)?.[0] || imei,
    imsi,
    iccid: text(valueAt(record, ['sim.iccid', 'iccid', 'endpoint.iccid']))
      ?? (kind === 'sms_mo' || kind === 'sms_mt' ? text(record.endpoint?.name) : null),
    msisdn: text(valueAt(record, ['sim.msisdn', 'msisdn', 'endpoint.msisdn'])),
    trafficType: text(record.traffic_type)
      ?? TRAFFIC_TYPES[record.traffic_type_id] ?? text(record.traffic_type_id),
    eventType: text(record.event_type)
      ?? EVENT_TYPES[record.event_type_id] ?? text(record.event_type_id),
    eventSeverity: text(record.event_severity)
      ?? EVENT_SEVERITIES[record.event_severity_id] ?? text(record.event_severity_id),
    isAlert: record.alert === true || record.alert === 1 ? 1 : 0,
    description: text(valueAt(record, ['description', 'event_type.description', 'traffic_type.description'])),
    operatorName: text(valueAt(record, [
      'operator.name', 'detail.operator.name', 'detail.pdp_context.operator.name',
      'operator_name',
    ])) ?? text(findNested(detail, ['operator_name', 'network_name']))
      ?? (record.operator_id !== undefined ? `Operator #${record.operator_id}` : null),
    operatorMnc: text(valueAt(record, [
      'operator.mnc', 'operator_mnc', 'detail.operator.mnc',
      'detail.pdp_context.mnc', 'detail_pdp_context_mnc',
    ])) ?? text(findNested(detail, ['mnc'])),
    countryName: text(valueAt(record, [
      'operator.country.name', 'operator_country_name', 'detail.operator.country.name',
    ])) ?? text(findNested(detail, ['country_name']))
      ?? (record.operator_country_id !== undefined ? `Country #${record.operator_country_id}` : null),
    countryMcc: text(valueAt(record, [
      'operator.country.mcc', 'country_mcc', 'detail.operator.country.mcc',
      'detail.pdp_context.mcc', 'detail_pdp_context_mcc',
    ])) ?? text(findNested(detail, ['mcc'])),
    endpointIp: text(valueAt(record, [
      'endpoint.ip_address', 'endpoint_ip_address', 'detail.pdp_context.ue_ip_address',
      'detail.pdp_context.ip_address', 'detail_pdp_context_ue_ip_address',
    ])) ?? text(findNested(detail, ['ue_ip_address', 'ip_address'])),
    apn: text(valueAt(record, ['detail.pdp_context.apn', 'detail_pdp_context_apn', 'detail.apn']))
      ?? text(findNested(detail, ['apn'])),
    ratType: (() => {
      const rat = scalar(valueAt(record, [
      'detail.pdp_context.rat_type', 'detail.rat_type', 'detail.radio_access_technology',
        'detail_pdp_context_rat_type', 'rat_type',
      ])) ?? scalar(findNested(detail, ['rat_type', 'radio_access_technology']));
      return rat === null ? null : RAT_TYPES[rat] ?? text(rat);
    })(),
    volumeTotal: number(valueAt(record, ['volume.total', 'volume_total', 'detail_volume_total'])),
    volumeTx: number(valueAt(record, ['volume.tx', 'volume_tx', 'detail_volume_tx'])),
    volumeRx: number(valueAt(record, ['volume.rx', 'volume_rx', 'detail_volume_rx'])),
    cost: number(record.cost),
    currencyCode: text(valueAt(record, ['currency.code', 'currency_code', 'currency.symbol', 'currency']))
      ?? (record.cost !== undefined ? 'EUR' : null),
    smsStatus: text(valueAt(record, ['status.status', 'status.description', 'status'])),
    smsPayload: text(record.payload),
    smsSource: text(record.source_address),
    smsDestination: text(valueAt(record, ['destination_address', 'dest_address'])),
    smsDcs: text(record.dcs),
    smsPartNumber: number(valueAt(record, ['multi_part_info.partno', 'multipart.part_number'])),
    smsTotalParts: number(valueAt(record, ['multi_part_info.total', 'multipart.total_parts'])),
    rawJson,
    dedupeKey,
  };
}

function authHeaderFromConfig(config) {
  if (!config) return null;
  const configured = config.header || config.token || config.basic_auth;
  if (configured) {
    const value = String(configured).trim();
    return /^Basic\s+/i.test(value) ? value : `Basic ${value}`;
  }
  if (config.username !== undefined && config.password !== undefined) {
    return `Basic ${Buffer.from(`${config.username}:${config.password}`).toString('base64')}`;
  }
  return null;
}

function secureEqual(actual, expected) {
  const a = Buffer.from(actual || '');
  const b = Buffer.from(expected || '');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { normalizeRecord, authHeaderFromConfig, secureEqual };
