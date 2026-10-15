import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const FIXTURE_URL = new URL('../fixtures/web-injection.json', import.meta.url);
const OPAQUE_VALUE = /\b[A-Za-z0-9_+/=-]{24,}\b/g;

function safeText(value) {
  if (typeof value !== 'string') return '';
  return value.replace(OPAQUE_VALUE, '[REDACTED]').slice(0, 500);
}

function loadFixture() {
  const fixture = JSON.parse(readFileSync(fileURLToPath(FIXTURE_URL), 'utf8'));
  if (!fixture || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_web_injection_fixture');
  }
  return fixture;
}

export function readAlerts(fixture = loadFixture()) {
  if (!fixture || !Array.isArray(fixture.alerts)) {
    throw new TypeError('invalid_web_injection_fixture');
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

const invokedPath = process.argv[1];
if (invokedPath && fileURLToPath(import.meta.url) === resolve(invokedPath)) {
  for (const row of readAlerts()) {
    process.stdout.write(`${JSON.stringify(row)}\n`);
  }
}
