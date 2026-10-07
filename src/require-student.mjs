import { readFile } from 'node:fs/promises';
import { createLoginVerifier } from './verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

let verifyLogin;

async function getVerifier() {
  if (verifyLogin) return verifyLogin;

  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseSecretKey) throw new Error('MISSING_SUPABASE_SECRET_KEY');

  verifyLogin = createLoginVerifier({ config, supabaseSecretKey });
  return verifyLogin;
}

export async function requireStudent(request, response) {
  try {
    const verifier = await getVerifier();
    const identity = await verifier(request.headers.authorization);

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
