import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ALERT_LOG_PATH = path.resolve(MODULE_DIR, '../alerts.log');
const DEFAULT_TTL_MS = 15 * 60 * 1000;

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
  if (result.action !== 'block' || !Number.isFinite(result.confidence) || result.confidence < 0.85) {
    return null;
  }

  const sourceAddress = alert?.data?.srcip;
  const alertId = alert?.id;
  if (!isValidIPv4(sourceAddress) || typeof alertId !== 'string' || alertId.length === 0) {
    return null;
  }

  return {
    effect: 'deny',
    match: { sourceAddress },
    expiresAt: new Date(now + ttlMs).toISOString(),
    evidenceAlertId: alertId,
    reason: result.reason,
  };
}

/**
 * Evaluate one alert, append one sanitized audit line, and return a temporary
 * deny-rule candidate only for a high-confidence block. The existing ZTNA
 * policy is not edited; callers may pass the candidate to their approved
 * policy adapter. No live enforcement API is invoked here.
 */
export async function respond(alert, options = {}) {
  const result = decide(alert);
  const now = Number.isFinite(options.now) ? options.now : Date.now();
  const ttlMs = Number.isFinite(options.ttlMs) && options.ttlMs > 0
    ? Math.min(options.ttlMs, 60 * 60 * 1000)
    : DEFAULT_TTL_MS;

  const denyRule = buildDenyRule(alert, result, now, ttlMs);
  const entry = {
    timestamp: new Date(now).toISOString(),
    alertId: safeLogText(alert?.id || 'unknown'),
    sourceAddress: isValidIPv4(alert?.data?.srcip) ? alert.data.srcip : null,
    action: result.action,
    confidence: result.confidence,
    reason: safeLogText(result.reason),
    outcome: denyRule ? 'temporary_deny_rule_candidate' : 'no_deny_rule',
  };

  await mkdir(path.dirname(ALERT_LOG_PATH), { recursive: true });
  await appendFile(ALERT_LOG_PATH, JSON.stringify(entry) + '\n', { encoding: 'utf8', mode: 0o600 });

  return {
    ...result,
    ...(denyRule ? { denyRule } : {}),
  };
}

export { ALERT_LOG_PATH };
