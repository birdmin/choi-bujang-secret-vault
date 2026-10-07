import config from '../aleph.config.json' with { type: 'json' };
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifyLogin;

async function getVerifier() {
  if (verifyLogin) return verifyLogin;

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl) {
    throw new Error('MISSING_SUPABASE_URL');
  }

  if (!supabaseSecretKey) {
    throw new Error('MISSING_SUPABASE_SECRET_KEY');
  }

  try {
    verifyLogin = createLoginVerifier({
      config,
      supabaseSecretKey,
    });
  } catch (error) {
    throw new Error(
      `VERIFIER_CREATE_FAILED:${error instanceof Error ? error.message : 'unknown'}`
    );
  }

  return verifyLogin;
}

export default async function handler(request, response) {
  let verifier;

  try {
    verifier = await getVerifier();
  } catch (error) {
    response.status(500).json({
      error: 'SERVER_CONFIG_ERROR',
      debug: error instanceof Error
        ? error.message
        : 'UNKNOWN_VERIFIER_ERROR',
    });
    return;
  }

  let identity;

  try {
    identity = await verifier(request.headers.authorization);
  } catch (error) {
    response.status(500).json({
      error: 'LOGIN_VERIFICATION_ERROR',
      debug: error instanceof Error
        ? error.message
        : 'UNKNOWN_LOGIN_VERIFICATION_ERROR',
    });
    return;
  }

  if (!identity || identity.kind !== 'student') {
    response.status(401).json({
      error: 'LOGIN_REQUIRED',
      debug: 'verify_login_rejected_token',
    });
    return;
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  const supabase = createClient(
    supabaseUrl,
    supabaseSecretKey,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
        detectSessionInUrl: false,
      },
    }
  );

  const { data, error } = await supabase
    .from('notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    response.status(500).json({
      error: 'NOTES_FETCH_FAILED',
    });
    return;
  }

  response.setHeader('Cache-Control', 'no-store');

  response.status(200).json({
    notes: data,
  });
}
