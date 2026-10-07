import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
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

  const root = resolve(import.meta.dirname, '..');
  const config = JSON.parse(
    await readFile(resolve(root, 'aleph.config.json'), 'utf8')
  );

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

  // 1. verifier 생성 단계 확인
  try {
    verifier = await getVerifier();
  } catch (error) {
    response.status(500).json({
      error: 'SERVER_CONFIG_ERROR',
      debug: error instanceof Error ? error.message : 'UNKNOWN_VERIFIER_ERROR',
    });
    return;
  }

  let identity;

  // 2. 실제 JWT 검증 단계 확인
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

  // 3. 로그인 검증이 성공한 뒤 자료 조회
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
