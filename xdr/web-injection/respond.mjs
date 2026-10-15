import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const XDR_DIR = join(MODULE_DIR, '..');
const ALERT_LOG = join(XDR_DIR, 'alerts.log');
const DENY_RULES_FILE = join(MODULE_DIR, 'deny-rules.json');
const BLOCK_THRESHOLD = 0.85;
const RULE_TTL_MS = 15 * 60 * 1000;

function safeString(value, maxLength = 200) {
  return typeof value === 'string'
    ? value.replace(/[\r\n\t]/g, ' ').slice(0, maxLength)
    : '';
}

function readDenyRules() {
  try {
    const parsed = JSON.parse(readFileSync(DENY_RULES_FILE, 'utf8'));
    return Array.isArray(parsed.rules) ? parsed.rules : [];
  } catch {
    return [];
  }
}

function writeDenyRules(rules) {
  writeFileSync(
    DENY_RULES_FILE,
    `${JSON.stringify({ schema: 'aleph.xdr.ztna-deny-candidates.v1', rules }, null, 2)}\n`,
    'utf8',
  );
}

function isSourceAddress(value) {
  if (typeof value !== 'string') return false;
  const address = value.trim();
  // Only accept an IP literal, never a user-supplied account or arbitrary string.
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(address)
    && address.split('.').every(part => Number(part) >= 0 && Number(part) <= 255);
  const ipv6 = /^[0-9a-f:]+$/i.test(address) && address.includes(':');
  return ipv4 || ipv6;
}

/**
 * Evaluate one web-injection alert, append an audit line, and persist a
 * short-lived deny candidate only for high-confidence block decisions.
 * Existing src/decider.mjs policy is intentionally not modified.
 */
export function respond(alert, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const decision = decide(alert);
  const alertId = safeString(alert?.id, 100);
  const rawSourceAddress = safeString(alert?.data?.srcip, 100);
  const sourceAddress = isSourceAddress(rawSourceAddress) ? rawSourceAddress : '';
  const shouldBlock = decision.action === 'block'
    && Number.isFinite(decision.confidence)
    && decision.confidence >= BLOCK_THRESHOLD
    && Boolean(alertId)
    && Boolean(sourceAddress);

  let denyRule = null;
  let outcome = decision.action === 'alert' ? 'alert_only' : 'record_only';

  if (shouldBlock) {
    const expiresAt = new Date(now.getTime() + RULE_TTL_MS).toISOString();
    denyRule = {
      id: `web-injection:${alertId}`,
      effect: 'deny',
      sourceAddress,
      createdAt: now.toISOString(),
      expiresAt,
      evidenceAlertId: alertId,
      reason: safeString(decision.reason, 200),
      confidence: decision.confidence,
    };
    const activeRules = readDenyRules().filter(rule =>
      rule
      && typeof rule.expiresAt === 'string'
      && Number.isFinite(Date.parse(rule.expiresAt))
      && Date.parse(rule.expiresAt) > now.getTime()
      && rule.id !== denyRule.id
    );
    activeRules.push(denyRule);
    writeDenyRules(activeRules);
    outcome = 'deny_candidate';

    // Adapter is explicit and optional; the existing decider policy is never rewritten.
    if (typeof options.installDenyRule === 'function') {
      options.installDenyRule(denyRule);
    }
  } else if (decision.action === 'block') {
    // A block without a trustworthy alert ID and source address must not create a rule.
    outcome = 'block_candidate_incomplete';
  }

  const logLine = {
    timestamp: now.toISOString(),
    module: 'web-injection',
    alertId: alertId || null,
    sourceAddress: sourceAddress || null,
    action: decision.action,
    confidence: decision.confidence,
    reason: safeString(decision.reason, 200),
    outcome,
    ...(denyRule ? { ruleId: denyRule.id, expiresAt: denyRule.expiresAt } : {}),
  };
  appendFileSync(ALERT_LOG, `${JSON.stringify(logLine)}\n`, { encoding: 'utf8', mode: 0o600 });

  return {
    ...decision,
    outcome,
    ...(denyRule ? { denyRule } : {}),
  };
}
