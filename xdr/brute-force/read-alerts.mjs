import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const FIXTURE_URL = new URL('../fixtures/brute-force.json', import.meta.url);
const SECRET_ASSIGNMENT = /\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer)\b\s*[:=]\s*[^\s,;]+/gi;
const LONG_SECRET_LIKE_VALUE = /\b[A-Za-z0-9_+/=-]{32,}\b/g;

function safeText(value) {
  if (typeof value !== 'string') return '';
  return value
    .replace(SECRET_ASSIGNMENT, '$1=[REDACTED]')
    .replace(LONG_SECRET_LIKE_VALUE, '[REDACTED]')
    .slice(0, 500);
}

function loadFixture() {
  const fixture = JSON.parse(readFileSync(fileURLToPath(FIXTURE_URL), 'utf8'));
  if (!fixture || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_brute_force_fixture');
  }
  return fixture;
}

/**
 * Return one safe summary row for every Wazuh-style alert.
 * Only timestamp, source address, account, rule level, and description are exposed.
 */
export function readAlerts(fixture = loadFixture()) {
  if (!fixture || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_brute_force_fixture');
  }

  const rows = fixture.alerts.map((alert) => ({
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: safeText(alert?.data?.srcuser),
    ruleLevel: Number.isInteger(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  }));

  if (rows.length !== fixture.alerts.length) {
    throw new Error('alert_row_count_mismatch');
  }
  return rows;
}

// When run directly, print exactly one JSON line per alert and no other output.
const invokedPath = process.argv[1];
if (invokedPath && fileURLToPath(import.meta.url) === resolve(invokedPath)) {
  for (const row of readAlerts()) {
    process.stdout.write(`${JSON.stringify(row)}\n`);
  }
}
