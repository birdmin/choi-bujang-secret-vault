import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const XDR_DIR = join(MODULE_DIR, '..');
const ALERT_LOG = join(XDR_DIR, 'alerts.log');
const DENY_RULES_FILE = join(XDR_DIR, 'brute-force', 'deny-rules.json');
const BLOCK_THRESHOLD = 0.85;
const RULE_TTL_MS = 15 * 60 * 1000;

function safeString(value, maxLength = 200) {
  return typeof value === 'string' ? value.replace(/[\r\n\t]/g, ' ').slice(0, maxLength) : '';
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
  writeFileSync(DENY_RULES_FILE, `${JSON.stringify({ schema: 'aleph.xdr.ztna-deny-candidates.v1', rules }, null, 2)}\n`, 'utf8');
}

/**
 * Evaluate one alert, append an audit line, and emit a short-lived ZTNA deny
 * candidate only for high-confidence block decisions. This module does not
 * edit the existing src/decider.mjs policy.
 */
export function respond(alert, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date();
  const decision = decide(alert);
  const alertId = safeString(alert?.id, 100);
  const sourceAddress = safeString(alert?.data?.srcip, 100);
  const outcome = decision.action === 'block' && decision.confidence >= BLOCK_THRESHOLD
    ? 'deny_candidate'
    : decision.action === 'alert' ? 'alert_only' : 'record_only';

  let denyRule = null;
  if (outcome === 'deny_candidate' && alertId && sourceAddress) {
    const expiresAt = new Date(now.getTime() + RULE_TTL_MS).toISOString();
    denyRule = {
      id: `brute-force:${alertId}`,
      effect: 'deny',
      sourceAddress,
      createdAt: now.toISOString(),
      expiresAt,
      evidenceAlertId: alertId,
      reason: decision.reason,
      confidence: decision.confidence,
    };

    const activeRules = readDenyRules().filter(rule =>
      rule && typeof rule.expiresAt === 'string'
      && Number.isFinite(Date.parse(rule.expiresAt))
      && Date.parse(rule.expiresAt) > now.getTime()
      && rule.id !== denyRule.id
    );
    activeRules.push(denyRule);
    writeDenyRules(activeRules);

    // Optional adapter hook for a host ZTNA policy store. The existing policy
    // is not rewritten here; the host decides how to accept this candidate.
    if (typeof options.installDenyRule === 'function') {
      options.installDenyRule(denyRule);
    }
  }

  const logLine = {
    timestamp: now.toISOString(),
    alertId: alertId || null,
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
