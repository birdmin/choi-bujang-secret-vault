import { createLoginVerifier } from '../src/verify-login.mjs';

let verifyLogin;

function getVerifier() {
  if (verifyLogin) return verifyLogin;

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    throw new Error('SERVER_CONFIG_ERROR');
  }

  const config = {
    judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
    publicAppUrl: 'https://choi-bujang-secret-vault-ten-coral.vercel.app/',
    identityProvider: {
      issuer: 'https://vkvajtqxmznshbwgoxiy.supabase.co/auth/v1',
      jwksUrl: 'https://vkvajtqxmznshbwgoxiy.supabase.co/auth/v1/.well-known/jwks.json',
      audience: 'authenticated',
    },
  };

  verifyLogin = createLoginVerifier({ config, supabaseSecretKey });
  return verifyLogin;
}

export default async function handler(request, response) {
  let identity;
  try {
    identity = await getVerifier()(request.headers.authorization);
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
  const supabase = (await import('@supabase/supabase-js')).createClient(
    supabaseUrl,
    supabaseSecretKey,
  );

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
