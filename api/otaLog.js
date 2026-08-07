const MONTHS = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

const LOG_RE = /^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) (\d+) "[^"]*" "([^"]*)"/;
const UA_RE = /^(?:\d+)-(\d{15})-(\d{14})-.*GL320M/;

function parseNginxTimestamp(value) {
  const match = String(value || '').match(
    /^(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/
  );
  if (!match || MONTHS[match[2]] === undefined) return null;
  const [, day, month, year, hour, minute, second, sign, offsetHour, offsetMinute] = match;
  const offset = (Number(offsetHour) * 60 + Number(offsetMinute)) * (sign === '+' ? 1 : -1);
  return new Date(Date.UTC(
    Number(year), MONTHS[month], Number(day),
    Number(hour), Number(minute), Number(second)
  ) - offset * 60_000).toISOString();
}

function parseLogLine(line) {
  const match = String(line || '').match(LOG_RE);
  if (!match) return null;
  const [, ip, nginxTimestamp, , reqPath, status, bytesSent, ua] = match;
  const userAgent = ua.match(UA_RE);
  if (!userAgent) return null;
  const imei = userAgent[1];
  const deviceTimestamp = userAgent[2];
  const timestamp = `${deviceTimestamp.slice(0,4)}-${deviceTimestamp.slice(4,6)}-${deviceTimestamp.slice(6,8)}T` +
    `${deviceTimestamp.slice(8,10)}:${deviceTimestamp.slice(10,12)}:${deviceTimestamp.slice(12,14)}Z`;
  return {
    imei,
    timestamp,
    requestedAt: parseNginxTimestamp(nginxTimestamp),
    ip,
    config: reqPath.replace(/^\//, ''),
    status: Number(status),
    bytesSent: Number(bytesSent),
  };
}

function isCompleteConfigDelivery(event, fileStat) {
  if (!event || !fileStat) return false;
  if (event.config !== `${event.imei}.ini`) return false;
  if (event.status !== 200 && event.status !== 206) return false;
  if (!event.requestedAt || new Date(event.requestedAt).getTime() < fileStat.mtimeMs) return false;
  return event.bytesSent >= fileStat.size;
}

module.exports = { parseLogLine, parseNginxTimestamp, isCompleteConfigDelivery };
