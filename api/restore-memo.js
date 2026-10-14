import config from '../aleph.config.json' with { type: 'json' };
import { createHash, timingSafeEqual } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { RESOURCE_IDS, markResource } from '../src/resource-ids.mjs';

let verifyLogin;
function db() {
  const url = process.env.SUPABASE_URL;
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secret) throw new Error('MISSING_SUPABASE_CONFIG');
  return createClient(url, secret, { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } });
}
async function verifier() {
  if (!verifyLogin) {
    const secret = process.env.SUPABASE_SECRET_KEY;
    if (!secret) throw new Error('MISSING_SUPABASE_SECRET_KEY');
    verifyLogin = createLoginVerifier({ config, supabaseSecretKey: secret });
  }
  return verifyLogin;
}
function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
function sameHash(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !/^[a-f0-9]{64}$/u.test(a) || !/^[a-f0-9]{64}$/u.test(b)) return false;
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}
function uuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

export default async function handler(request, response) {
  markResource(response, RESOURCE_IDS.studentMemos);
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Pragma', 'no-cache');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  let identity;
  try {
    identity = await (await verifier())(request.headers.authorization);
  } catch {
    response.status(500).json({ error: 'LOGIN_VERIFICATION_ERROR' });
    return;
  }

  // This exercise route is deliberately limited to the judge's B test identity.
  // Ordinary student sessions and identity A cannot invoke it.
  if (!identity || identity.kind !== 'judge' || identity.identity !== 'b') {
    response.status(403).json({ error: 'TEST_IDENTITY_B_REQUIRED' });
    return;
  }

  const memoId = request.body?.memoId;
  if (!uuid(memoId)) {
    response.status(400).json({ error: 'INVALID_MEMO_ID' });
    return;
  }

  const client = db();
  const { data: snapshot, error: snapshotError } = await client
    .from('private_memo_snapshots')
    .select('memo_id,owner_id,title,body,content_sha256,test_identity')
    .eq('memo_id', memoId)
    .eq('test_identity', 'b')
    .maybeSingle();

  if (snapshotError) {
    response.status(500).json({ error: 'PRIVATE_SNAPSHOT_LOOKUP_FAILED' });
    return;
  }
  if (!snapshot) {
    response.status(404).json({ error: 'PRIVATE_SNAPSHOT_NOT_FOUND' });
    return;
  }
  if (!uuid(snapshot.owner_id) || typeof snapshot.title !== 'string'
    || typeof snapshot.body !== 'string'
    || !sameHash(snapshot.content_sha256, sha256(snapshot.body))) {
    response.status(409).json({ error: 'PRIVATE_SNAPSHOT_INTEGRITY_FAILED' });
    return;
  }

  // Compare the target's ID, owner and content hash before changing anything.
  const { data: current, error: currentError } = await client
    .from('memos')
    .select('id,owner_id,title,body')
    .eq('id', memoId)
    .maybeSingle();

  if (currentError) {
    response.status(500).json({ error: 'CURRENT_MEMO_LOOKUP_FAILED' });
    return;
  }
  if (current && current.owner_id !== snapshot.owner_id) {
    response.status(409).json({ error: 'MEMO_OWNER_MISMATCH' });
    return;
  }
  if (current && current.id !== snapshot.memo_id) {
    response.status(409).json({ error: 'MEMO_ID_MISMATCH' });
    return;
  }

  const restoredHash = sha256(snapshot.body);
  if (!sameHash(restoredHash, snapshot.content_sha256)) {
    response.status(409).json({ error: 'MEMO_CONTENT_HASH_MISMATCH' });
    return;
  }

  let restored;
  let writeError;
  if (current) {
    const result = await client.from('memos')
      .update({ title: snapshot.title, body: snapshot.body, owner_id: snapshot.owner_id, updated_at: new Date().toISOString() })
      .eq('id', snapshot.memo_id)
      .eq('owner_id', snapshot.owner_id)
      .select('id,owner_id,title,body')
      .maybeSingle();
    restored = result.data;
    writeError = result.error;
  } else {
    const result = await client.from('memos')
      .insert({ id: snapshot.memo_id, owner_id: snapshot.owner_id, title: snapshot.title, body: snapshot.body })
      .select('id,owner_id,title,body')
      .maybeSingle();
    restored = result.data;
    writeError = result.error;
  }

  if (writeError || !restored) {
    response.status(500).json({ error: 'SINGLE_MEMO_RESTORE_FAILED' });
    return;
  }
  if (restored.id !== snapshot.memo_id || restored.owner_id !== snapshot.owner_id
    || !sameHash(sha256(restored.body), snapshot.content_sha256)) {
    response.status(409).json({ error: 'RESTORED_MEMO_VERIFICATION_FAILED' });
    return;
  }

  const { error: auditError } = await client.from('memo_restore_audit').insert({
    memo_id: restored.id,
    owner_id: restored.owner_id,
    content_sha256: snapshot.content_sha256,
    snapshot_source: 'private_memo_snapshots',
    test_identity: 'b',
    event: 'single_virtual_memo_restored'
  });
  if (auditError) {
    response.status(500).json({ error: 'RESTORE_AUDIT_WRITE_FAILED' });
    return;
  }

  response.status(200).json({
    restored: true,
    memo: { id: restored.id, owner_id: restored.owner_id, content_sha256: sha256(restored.body) },
    audit: 'appended',
    scope: 'one_virtual_memo_only'
  });
}
