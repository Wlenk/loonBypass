// Updates happen in GitHub Actions, followed by an atomic Worker deployment.
// The request path never downloads or compiles an upstream rule list.
import { MIHOMO_FILES, PROFILE_PATH, serveProfile } from './mihomo.js';
const RULESETS = ['netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn',
  'netease-other', 'tencent', 'alibaba', 'china'];
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!['GET', 'HEAD'].includes(request.method)) {
      return new Response('Method not allowed', { status: 405 });
    }
    try {
      if (url.pathname === '/subscription/mihomo.yaml') return await serveProfile(request, env.ASSETS);
      if (url.pathname === '/health') {
        const response = await env.ASSETS.fetch(new Request(new URL('/manifest.json', url)));
        if (!response.ok) throw new Error('manifest missing');
        const manifest = await response.json();
        const age = Date.now() - Date.parse(manifest.checked_at);
        const names = Object.keys(manifest.files ?? {});
        let ok = manifest.schema === 1 && names.sort().join() === [...RULESETS].sort().join() &&
          Number.isFinite(age) && age >= -300000 && age < 72 * 3600000;
        let mihomoVersion;
        if (manifest.mihomo) {
          const [converted, sealed] = await Promise.all([
            env.ASSETS.fetch(new Request(new URL('/mihomo/manifest.json', url))),
            env.ASSETS.fetch(new Request(new URL(PROFILE_PATH, url))),
          ]);
          if (!converted.ok || !sealed.ok) throw Error('Mihomo bundle missing');
          const child = await converted.json();
          const encrypted = await sealed.arrayBuffer();
          const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', encrypted))]
            .map(byte => byte.toString(16).padStart(2, '0')).join('');
          const envelope = JSON.parse(new TextDecoder().decode(encrypted));
          mihomoVersion = child.version;
          ok &&= manifest.mihomo.path === '/mihomo/manifest.json' &&
            manifest.mihomo.files === Object.keys(MIHOMO_FILES).length && child.schema === 1 &&
            child.version === manifest.mihomo.version && child.source_version === manifest.version &&
            child.checked_at === manifest.checked_at && digest === child.profile_sha256 &&
            envelope.schema === 1 && typeof envelope.ciphertext === 'string' &&
            Object.keys(child.files ?? {}).sort().join() === Object.keys(MIHOMO_FILES).sort().join();
        }
        return Response.json({ ok, version: manifest.version, checked_at: manifest.checked_at,
          rulesets: names.length, ...(mihomoVersion ? { mihomo_version: mihomoVersion,
            mihomo_rulesets: Object.keys(MIHOMO_FILES).length } : {}) },
          { status: ok ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
      }
      if (url.pathname !== '/manifest.json' &&
          !RULESETS.some(name => url.pathname === `/rules/${name}.list`) &&
          url.pathname !== '/mihomo/manifest.json' &&
          !Object.values(MIHOMO_FILES).some(file => url.pathname === file.path)) {
        return new Response('Rule service: /health, /manifest.json, /rules/*.list, /mihomo/', { status: 404 });
      }
      const response = await env.ASSETS.fetch(request);
      if (!response.ok && response.status !== 304) throw new Error('asset unavailable');
      const headers = new Headers(response.headers);
      headers.set('Cache-Control', 'public, max-age=300');
      headers.set('X-Content-Type-Options', 'nosniff');
      if (url.pathname.endsWith('.list')) headers.set('Content-Type', 'text/plain; charset=utf-8');
      if (url.pathname.endsWith('.mrs')) headers.set('Content-Type', 'application/octet-stream');
      return new Response(response.body, { status: response.status, headers });
    } catch {
      // Never return an empty successful ruleset after an exception.
      return new Response('Verified rules unavailable; retain the previous downloaded rules.',
        { status: 503, headers: { 'Cache-Control': 'no-store', 'Retry-After': '300' } });
    }
  }
};
