import { createClient } from '@supabase/supabase-js';

function readCookie(request, name) {
  const prefix = name + '=';
  const item = (request.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith(prefix));
  if (!item) return '';
  try { return decodeURIComponent(item.slice(prefix.length)); } catch { return ''; }
}

function supabase() {
  const url = process.env.SUPABASE_URL;
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secret) throw new Error('MISSING_SUPABASE_CONFIG');
  return createClient(url, secret, { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } });
}

function clearCookies(response) {
  response.setHeader('Set-Cookie', [
    'byte-back-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
    'byte-back-refresh=; Path=/api/auth; HttpOnly; Secure; SameSite=Strict; Max-Age=0'
  ]);
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  const accessToken = readCookie(request, 'byte-back-session');
  const refreshToken = readCookie(request, 'byte-back-refresh');
  if (!accessToken && !refreshToken) {
    response.status(401).json({ error: 'LOGIN_REQUIRED' });
    return;
  }

  try {
    const client = supabase();
    const { data, error } = await client.auth.setSession({
      access_token: accessToken,
      refresh_token: refreshToken
    });
    if (error || !data?.session || !data?.user) {
      clearCookies(response);
      response.status(401).json({ error: 'LOGIN_REQUIRED' });
      return;
    }

    response.setHeader('Set-Cookie', [
      `byte-back-session=${encodeURIComponent(data.session.access_token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`,
      `byte-back-refresh=${encodeURIComponent(data.session.refresh_token)}; Path=/api/auth; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`
    ]);
    response.status(200).json({
      access_token: data.session.access_token,
      user: { id: data.user.id, email: data.user.email }
    });
  } catch {
    response.status(500).json({ error: 'SESSION_RESTORE_FAILED' });
  }
}
