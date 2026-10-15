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

  if (request.method !== 'POST') {
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
    response.status(401).json({ error: 'LOGIN_REQUIRED' });
    return;
  }

  const token = request.body?.deviceToken;
  if (!validDeviceToken(token)) {
    response.status(400).json({ error: 'INVALID_DEVICE_TOKEN' });
    return;
  }

  try {
    const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
    const client = supabase();
    const { data: existing, error: lookupError } = await client
      .from('device_approvals')
      .select('status')
      .eq('owner_id', identity.userId)
      .eq('device_token_hash', tokenHash)
      .maybeSingle();

    if (lookupError) {
      response.status(500).json({ error: 'DEVICE_APPROVAL_LOOKUP_FAILED' });
      return;
    }

    if (existing) {
      response.status(200).json({
        requested: true,
        status: existing.status,
        approved: existing.status === 'approved'
      });
      return;
    }

    const { error: insertError } = await client.from('device_approvals').insert({
      owner_id: identity.userId,
      device_token_hash: tokenHash,
      status: 'pending'
    });

    if (insertError) {
      // A unique-token race must not accidentally approve the device.
      response.status(insertError.code === '23505' ? 409 : 500).json({
        error: insertError.code === '23505'
          ? 'DEVICE_TOKEN_ALREADY_REGISTERED'
          : 'DEVICE_APPROVAL_REQUEST_FAILED'
      });
      return;
    }

    response.status(201).json({
      requested: true,
      status: 'pending',
      approved: false
    });
  } catch {
    response.status(500).json({ error: 'DEVICE_APPROVAL_REQUEST_FAILED' });
  }
}
