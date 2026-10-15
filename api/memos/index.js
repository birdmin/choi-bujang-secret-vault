```javascript
import config from '../../aleph.config.json' with { type: 'json' };
import { createHash, randomUUID } from 'node:crypto';
import { RESOURCE_IDS, markResource } from '../../src/resource-ids.mjs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../../src/verify-login.mjs';

let verifyLogin;

async function getVerifier() {
  if (verifyLogin) return verifyLogin;
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (!secret) throw new Error('MISSING_SUPABASE_SECRET_KEY');
  verifyLogin = createLoginVerifier({ config, supabaseSecretKey: secret });
  return verifyLogin;
}

function supabase() {
  const url = process.env.SUPABASE_URL;
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secret) throw new Error('MISSING_SUPABASE_CONFIG');

  return createClient(url, secret, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  });
}

function readDeviceCookie(request) {
  const raw = request.headers.cookie || '';
  const entry = raw
    .split(';')
    .map(part => part.trim())
    .find(part => part.startsWith('byte-back-device='));

  const token = entry
    ? decodeURIComponent(entry.slice('byte-back-device='.length))
    : '';

  return /^[a-f0-9]{64}$/.test(token) ? token : null;
}

async function authenticate(request, response) {
  try {
    const identity = await (await getVerifier())(request.headers.authorization);

    if (!identity || identity.kind !== 'student') {
      response.status(401).json({ error: 'LOGIN_REQUIRED' });
      return null;
    }

    return identity;
  } catch {
    response.status(500).json({ error: 'LOGIN_VERIFICATION_ERROR' });
    return null;
  }
}

async function requireApprovedDevice(request, response, identity, db) {
  const token = readDeviceCookie(request);

  if (!token) {
    response.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
    return false;
  }

  const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');

  const { data, error } = await db
    .from('device_approvals')
    .select('id')
    .eq('owner_id', identity.userId)
    .eq('device_token_hash', tokenHash)
    .eq('status', 'approved')
    .maybeSingle();

  if (error) {
    response.status(503).json({ error: 'DEVICE_APPROVAL_CHECK_FAILED' });
    return false;
  }

  if (!data) {
    response.status(403).
