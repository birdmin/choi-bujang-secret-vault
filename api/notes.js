import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifyLogin;

async function getVerifier() {
  if (verifyLogin) return verifyLogin;

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  const supabasePublishableKey = process.env.SUPABASE_PUBLISHABLE_KEY;

  if (!supabaseUrl || !supabaseSecretKey) throw new Error('SERVER_CONFIG_ERROR');

  const root = resolve(import.meta.dirname, '..');
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
  const verifierClient = createClient(
    supabaseUrl,
    supabasePublishableKey || supabaseSecretKey,
    { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } },
  );
  verifyLogin = createLoginVerifier({
    config,
    supabaseSecretKey,
    supabaseClient: verifierClient,
  });
  return verifyLogin;
}

export default async function handler(request, response) {
  let identity;
  try {
    identity = await (await getVerifier())(request.headers.authorization);
  } catch {
    response.status(500).json({ error: 'SERVER_CONFIG_ERROR' });
    return;
  }

  if (!identity || identity.kind !== 'student') {
    response.status(401).json({ error: 'LOGIN_REQUIRED' });
    return;
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  const supabase = createClient(supabaseUrl, supabaseSecretKey);
  const { data, error } = await supabase
    .from('notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    response.status(500).json({ error: 'NOTES_FETCH_FAILED' });
    return;
  }

  response.setHeader('Cache-Control', 'no-store');
  response.status(200).json({ notes: data });
}
