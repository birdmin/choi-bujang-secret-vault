import { createClient } from '@supabase/supabase-js';

function supabase() {
  const url = process.env.SUPABASE_URL;
  const secret = process.env.SUPABASE_SECRET_KEY;

  if (!url || !secret) {
    throw new Error('MISSING_SUPABASE_CONFIG');
  }

  return createClient(url, secret, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false
    }
  });
}

export default async function handler(request, response) {
  if (request.method !== 'POST') {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  const { email, password } = request.body ?? {};

  if (typeof email !== 'string' || typeof password !== 'string') {
    response.status(400).json({ error: 'INVALID_LOGIN' });
    return;
  }

  try {
    const { data, error } = await supabase().auth.signInWithPassword({
      email: email.trim(),
      password
    });

    if (error || !data?.session || !data?.user) {
      response.status(401).json({ error: 'INVALID_LOGIN' });
      return;
    }

    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Set-Cookie', [
      `byte-back-session=${encodeURIComponent(data.session.access_token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`,
      `byte-back-refresh=${encodeURIComponent(data.session.refresh_token)}; Path=/api/auth; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`
    ]);
    response.status(200).json({
      access_token: data.session.access_token,
      user: {
        id: data.user.id,
        email: data.user.email
      }
    });
  } catch {
    response.status(500).json({ error: 'LOGIN_SERVER_ERROR' });
  }
}
