import config from '../aleph.config.json' with { type: 'json' };
import { RESOURCE_IDS, markResource } from '../src/resource-ids.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifyLogin;

async function getVerifier() {
  if (verifyLogin) return verifyLogin;

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    throw new Error('SERVER_CONFIG_INVALID');
  }

  verifyLogin = createLoginVerifier({ config, supabaseSecretKey });
  return verifyLogin;
}

export default async function handler(request, response) {
  markResource(response, RESOURCE_IDS.instructorNotices);
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'GET') {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }

  let identity;
  try {
    const verifier = await getVerifier();
    identity = await verifier(request.headers.authorization);
  } catch {
    response.status(500).json({ error: 'LOGIN_VERIFICATION_ERROR' });
    return;
  }

  if (!identity) {
    response.status(401).json({ error: 'LOGIN_REQUIRED' });
    return;
  }

  // This endpoint is classified as instructor notices. The repository currently
  // has no persisted instructor-role/permission source to authorize access.
  // Fail closed instead of trusting a request-body role or exposing every note.
  if (identity.kind !== 'instructor') {
    response.status(403).json({ error: 'INSTRUCTOR_PERMISSION_REQUIRED' });
    return;
  }

  // No instructor identity can currently be produced by verify-login.mjs.
  // Keep this endpoint closed until server-verified instructor permissions exist.
  response.status(403).json({ error: 'INSTRUCTOR_PERMISSION_REQUIRED' });
}
