// These paths and formats also constrain the external integrity verifier.
export const MIHOMO_FILES = Object.fromEntries([
  ...['netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn',
    'netease-other', 'tencent', 'alibaba', 'china-other'].map(name =>
    [name, { path: `/mihomo/${name}.list`, behavior: 'classical', format: 'text' }]),
  ['china-domain', { path: '/mihomo/china-domain.mrs', behavior: 'domain', format: 'mrs' }],
  ['china-ipcidr', { path: '/mihomo/china-ipcidr.mrs', behavior: 'ipcidr', format: 'mrs' }],
]);
export const PROFILE_PATH = '/sealed-profiles/windows-mihomo.json';
export const PROFILE_AAD = 'loon-malaysia-rules:mihomo-profile:v1';

export function decodeBase64(text) {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let index = 0; index < raw.length; index++) bytes[index] = raw.charCodeAt(index);
  return bytes;
}

export async function serveProfile(request, assets) {
  const url = new URL(request.url);
  const tokens = url.searchParams.getAll('token');
  if (tokens.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(tokens[0])) {
    return new Response('Subscription not found', { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
  // The 256-bit capability is supplied only by its owner. Public repository and
  // Worker assets store AES-GCM ciphertext; no node password is committed.
  const response = await assets.fetch(new Request(new URL(PROFILE_PATH, url)));
  if (!response.ok) throw Error('sealed profile unavailable');
  const envelope = await response.json();
  if (envelope.schema !== 1) throw Error('sealed profile schema');
  let plaintext;
  try {
    const key = await crypto.subtle.importKey('raw',
      decodeBase64(tokens[0].replaceAll('-', '+').replaceAll('_', '/') + '='),
      { name: 'AES-GCM' }, false, ['decrypt']);
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM',
      iv: decodeBase64(envelope.nonce), additionalData: new TextEncoder().encode(PROFILE_AAD) },
    key, decodeBase64(envelope.ciphertext));
  } catch {
    return new Response('Subscription not found', { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
  return new Response(request.method === 'HEAD' ? null : plaintext, { headers: {
    'Content-Type': 'application/yaml; charset=utf-8',
    'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff',
    'X-Robots-Tag': 'noindex, nofollow',
    'Content-Disposition': 'inline; filename="Mihomo-Malaysia.yaml"',
    'profile-update-interval': '6',
  } });
}
