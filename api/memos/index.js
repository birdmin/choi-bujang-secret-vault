import config from '../../aleph.config.json' with { type: 'json' };
import { createHash, randomUUID } from 'node:crypto';
import { RESOURCE_IDS, markResource, withResourceId } from '../../src/resource-ids.mjs';
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
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false }
  });
}

function readDeviceCookie(request) {
  const raw = request.headers.cookie || '';
  const entry = raw.split(';').map(part => part.trim())
    .find(part => part.startsWith('byte-back-device='));
  const token = entry ? decodeURIComponent(entry.slice('byte-back-device='.length)) : '';
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
  } catch (error) {
    console.error('memos: login verification failed', error?.message);
    response.status(500).json({ error: 'LOGIN_VERIFICATION_ERROR' });
    return null;
  }
}

async function requireApprovedDevice(request, response, identity, client) {
  let token;
  try {
    token = readDeviceCookie(request);
  } catch {
    response.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
    return false;
  }

  if (!token) {
    response.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
    return false;
  }

  const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');
  const { data, error } = await client
    .from('device_approvals')
    .select('id')
    .eq('owner_id', identity.userId)
    .eq('device_token_hash', tokenHash)
    .eq('status', 'approved')
    .maybeSingle();

  if (error) {
    console.error('memos: device approval lookup failed', error.code, error.message);
    response.status(503).json({ error: 'DEVICE_APPROVAL_CHECK_FAILED' });
    return false;
  }
  if (!data) {
    response.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
    return false;
  }
  return true;
}

export default async function handler(request, response) {
  markResource(response, RESOURCE_IDS.studentMemos);
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'GET' && request.method !== 'POST') {
    response.setHeader('Allow', 'GET, POST');
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  const identity = await authenticate(request, response);
  if (!identity) return;

  let client;
  try {
    client = supabase();
  } catch (error) {
    console.error('memos: Supabase configuration failed', error?.message);
    response.status(500).json({ error: 'MISSING_SUPABASE_CONFIG' });
    return;
  }

  if (!(await requireApprovedDevice(request, response, identity, client))) return;

  if (request.method === 'GET') {
    const { data, error } = await client
      .from('memos')
      .select('id,title,body,created_at,updated_at')
      .eq('owner_id', identity.userId)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('memos: list query failed', error.code, error.message);
      response.status(500).json({ error: 'MEMO_LIST_FAILED' });
      return;
    }

    response.status(200).json({
      memos: (data || []).map(memo => withResourceId(RESOURCE_IDS.studentMemos, memo)),
      count: (data || []).length
    });
    return;
  }

  const body = request.body ?? {};
  const title = body.title;
  const memoBody = body.body;
  if (typeof title !== 'string' || typeof memoBody !== 'string' ||
      !title.trim() || title.length > 200 || memoBody.length > 50000) {
    response.status(400).json({ error: 'INVALID_MEMO' });
    return;
  }

  const { data, error } = await client
    .from('memos')
    .insert({
      id: randomUUID(),
      owner_id: identity.userId,
      title: title.trim(),
      body: memoBody
    })
    .select('id,title,body,created_at,updated_at')
    .single();

  if (error) {
    console.error('memos: insert failed', error.code, error.message);
    response.status(500).json({ error: 'MEMO_CREATE_FAILED' });
    return;
  }

  response.status(201).json(withResourceId(RESOURCE_IDS.studentMemos, data));
}
