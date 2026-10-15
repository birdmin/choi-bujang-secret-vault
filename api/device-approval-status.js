import config from '../aleph.config.json' with { type: 'json' };
import { createHash } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

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
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false }
  });
}

function validDeviceToken(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{32,200}$/.test(value);
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'GET') {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  let identity;
  try {
    identity = await (await getVerifier())(request.headers.authorization);
  } catch {
    response.status(500).json({ error: 'LOGIN_VERIFICATION_ERROR' });
    return;
  }

  if (!identity || identity.kind !== 'student') {
    response.status(401).json({ error: 'LOGIN_REQUIRED', approved: false });
    return;
  }

  const token = request.headers['x-device-token'];
  if (!validDeviceToken(token)) {
    response.status(200).json({ approved: false, status: 'unregistered' });
    return;
  }

  try {
    const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
    const { data, error } = await supabase()
      .from('device_approvals')
      .select('status')
      .eq('owner_id', identity.userId)
      .eq('device_token_hash', tokenHash)
      .maybeSingle();

    if (error) {
      response.status(500).json({ error: 'DEVICE_APPROVAL_LOOKUP_FAILED', approved: false });
      return;
    }

    response.status(200).json({
      approved: data?.status === 'approved',
      status: data?.status ?? 'unregistered'
    });
  } catch {
    response.status(500).json({ error: 'DEVICE_APPROVAL_LOOKUP_FAILED', approved: false });
  }
}
