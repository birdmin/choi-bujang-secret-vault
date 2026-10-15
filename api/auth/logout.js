export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    return;
  }
  response.setHeader('Set-Cookie', [
    'byte-back-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
    'byte-back-refresh=; Path=/api/auth; HttpOnly; Secure; SameSite=Strict; Max-Age=0'
  ]);
  response.status(200).json({ ok: true });
}
