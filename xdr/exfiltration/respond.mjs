import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ALERT_LOG_PATH = path.resolve(MODULE_DIR, '../alerts.log');
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_TTL_MS = 60 * 60 * 1000;
const MIN_BLOCK_CONFIDENCE = 0.85;

function isValidIPv4(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) =>
    /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255
  );
}

function safeLogText(value) {
  return String(value ?? '')
    .replace(/[\r\n\t]/gu, ' ')
    .replace(/Bearer\s+[^\s,;]+/giu, 'Bearer [REDACTED]')
    .replace(/(?:password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+/giu, '[REDACTED]');
}

function buildDenyRule(alert, result, now, ttlMs) {
  if (result.action !== 'block'
    || !Number.isFinite(result.confidence)
    || result.confidence < MIN_BLOCK_CONFIDENCE) return null;

  const destinationAddress = alert?.data?.dstip;
  const account = alert?.data?.srcuser;
  const alertId = alert?.id;

  // Require a concrete external destination, account, and evidence ID.
  // Scope the candidate to the destination and account; never block an
  // entire source network or create a rule for a normal/ambiguous event.
  if (!isValidIPv4(destinationAddress)
    || typeof account !== 'string'
    || !/^[a-zA-Z0-9._-]{1,64}$/.test(account)
    || typeof alertId !== 'string'
    || !/^ex-[a-zA-Z0-9._-]{1,76}$/.test(alertId)) return null;

  return {
    effect: 'deny',
    match: { destinationAddress, account },
    expiresAt: new Date(now + ttlMs).toISOString(),
    evidenceAlertId: alertId,
    reason: result.reason,
  };
}

/**
 * Evaluate one exfiltration alert, append a sanitized audit line, and return
 * a temporary deny-rule candidate only for high-confidence block decisions.
 * This produces a candidate for the existing ZTNA policy to evaluate; it does
 * not edit or replace existing ZTNA rules and does not enforce a live block.
 */
export async function respond(alert, options = {}) {
  const result = decide(alert);
  const now = Number.isFinite(options.now) ? options.now : Date.now();
  const ttlMs = Number.isFinite(options.ttlMs) && options.ttlMs > 0
    ? Math.min(options.ttlMs, MAX_TTL_MS)
    : DEFAULT_TTL_MS;
  const denyRule = buildDenyRule(alert, result, now, ttlMs);

  const entry = {
    timestamp: new Date(now).toISOString(),
    alertId: safeLogText(alert?.id || 'unknown'),
    action: result.action,
    confidence: result.confidence,
    reason: safeLogText(result.reason),
    outcome: denyRule ? 'temporary_deny_rule_candidate' : 'no_deny_rule',
    ...(denyRule ? {
      destinationAddress: denyRule.match.destinationAddress,
      expiresAt: denyRule.expiresAt,
      evidenceAlertId: denyRule.evidenceAlertId,
    } : {}),
  };

  await mkdir(path.dirname(ALERT_LOG_PATH), { recursive: true });
  await appendFile(ALERT_LOG_PATH, JSON.stringify(entry) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
  });

  return {
    ...result,
    ...(denyRule ? { denyRule } : {}),
  };
}

export { ALERT_LOG_PATH };
