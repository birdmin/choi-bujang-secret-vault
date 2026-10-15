```javascript
import config from '../../aleph.config.json' with { type: 'json' };
import { createHash } from 'node:crypto';
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

function db() {
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

function validUuid(value) {
  return typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
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

async function requireApprovedDevice(request, response, identity, client) {
  const token = readDeviceCookie(request);

  if (!token) {
    response.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
    return false;
  }

  const tokenHash = createHash('sha256')
    .update(token, 'utf8')
    .digest('hex');

  const { data, error } = await client
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
    response.status(403).json({ error: 'DEVICE_NOT_APPROVED' });
    return false;
  }

  return true;
}

export default async function handler(request, response) {
  markResource(response, RESOURCE_IDS.studentMemos);

  const identity = await authenticate(request, response);
  if (!identity) return;

  const id = request.query?.id;
  if (!validUuid(id)) {
    response.status(400).json({ error: 'INVALID_ID' });
    return;
  }

  let client;
  try {
    client = db();
  } catch {
    response.status(500).json({ error: 'MISSING_SUPABASE_CONFIG' });
    return;
  }

  if (!(await requireApprovedDevice(request, response, identity, client))) return;

  // Stage 4 savepoint: detail endpoints enforce ownership with the verified identity.
  if (request.method === 'GET') {
    const { data, error } = await client
      .from('memos')
      .select('id,title,body')
      .eq('id', id)
      .eq('owner_id', identity.userId)
      .maybeSingle();

    if (error) {
      response.status(500).json({ error: 'MEMO_FETCH_FAILED' });
      return;
    }

    if (!data) {
      response.status(404).json({ error: 'MEMO_NOT_FOUND' });
      return;
    }

    response.setHeader('Cache-Control', 'no-store');
    response.status(200).json(withResourceId(RESOURCE_IDS.studentMemos, data));
    return;
  }

  if (request.method === 'PUT') {
    const { title, body } = request.body ?? {};

    if (typeof title !== 'string' || typeof body !== 'string') {
      response.status(400).json({ error: 'INVALID_MEMO' });
      return;
    }

    const { data: existing, error: fetchError } = await client
      .from('memos')
      .select('id,owner_id')
      .eq('id', id)
      .maybeSingle();

    if (fetchError) {
      response.status(500).json({ error: 'MEMO_FETCH_FAILED' });
      return;
    }

    if (!existing) {
      response.status(404).json({ error: 'MEMO_NOT_FOUND' });
      return;
    }

    if (existing.owner_id !== identity.userId) {
      response.status(403).json({ error: 'MEMO_FORBIDDEN' });
      return;
    }

    const { data, error } = await client
      .from('memos')
      .update({
        title,
        body,
        owner_id: identity.userId,
        updated_at: new Date().toISOString()
      })
      .eq('id', id)
      .eq('owner_id', identity.userId)
      .select('id,title,body')
      .maybeSingle();

    if (error) {
      response.status(500).json({ error: 'MEMO_UPDATE_FAILED' });
      return;
    }

    if (!data) {
      response.status(403).json({ error: 'MEMO_FORBIDDEN' });
      return;
    }

    response.status(200).json(withResourceId(RESOURCE_IDS.studentMemos, data));
    return;
  }

  if (request.method === 'DELETE') {
    const { data: existing, error: fetchError } = await client
      .from('memos')
      .select('id,owner_id')
      .eq('id', id)
      .maybeSingle();

    if (fetchError) {
      response.status(500).json({ error: 'MEMO_FETCH_FAILED' });
      return;
    }

    if (!existing) {
      response.status(404).json({ error: 'MEMO_NOT_FOUND' });
      return;
    }

    if (existing.owner_id !== identity.userId) {
      response.status(403).json({ error: 'MEMO_FORBIDDEN' });
      return;
    }

    const { data, error } = await client
      .from('memos')
      .delete()
      .eq('id', id)
      .eq('owner_id', identity.userId)
      .select('id')
      .maybeSingle();

    if (error) {
      response.status(500).json({ error: 'MEMO_DELETE_FAILED' });
      return;
    }

    if (!data) {
      response.status(403).json({ error: 'MEMO_FORBIDDEN' });
      return;
    }

    response.status(204).end();
    return;
  }

  response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}
```
