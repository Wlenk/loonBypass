// Updates happen in GitHub Actions, followed by an atomic Worker deployment.
// The request path never downloads or compiles an upstream rule list.
const RULESETS = ['netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn',
  'netease-other', 'tencent', 'alibaba', 'china'];
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!['GET', 'HEAD'].includes(request.method)) {
      return new Response('Method not allowed', { status: 405 });
    }
    try {
      if (url.pathname === '/health') {
        const response = await env.ASSETS.fetch(new Request(new URL('/manifest.json', url)));
        if (!response.ok) throw new Error('manifest missing');
        const manifest = await response.json();
        const age = Date.now() - Date.parse(manifest.checked_at);
        const names = Object.keys(manifest.files ?? {});
        const ok = manifest.schema === 1 && names.sort().join() === [...RULESETS].sort().join() &&
          Number.isFinite(age) && age >= -300000 && age < 72 * 3600000;
        return Response.json({ ok, version: manifest.version, checked_at: manifest.checked_at,
          rulesets: names.length },
          { status: ok ? 200 : 503, headers: { 'Cache-Control': 'no-store' } });
      }
      if (url.pathname !== '/manifest.json' &&
          !RULESETS.some(name => url.pathname === `/rules/${name}.list`)) {
        return new Response('Loon rule service: /health, /manifest.json, /rules/*.list', { status: 404 });
      }
      const response = await env.ASSETS.fetch(request);
      if (!response.ok && response.status !== 304) throw new Error('asset unavailable');
      const headers = new Headers(response.headers);
      headers.set('Cache-Control', 'public, max-age=300');
      headers.set('X-Content-Type-Options', 'nosniff');
      if (url.pathname.endsWith('.list')) headers.set('Content-Type', 'text/plain; charset=utf-8');
      return new Response(response.body, { status: response.status, headers });
    } catch {
      // Never return an empty successful ruleset after an exception.
      return new Response('Verified rules unavailable; retain the previous downloaded rules.',
        { status: 503, headers: { 'Cache-Control': 'no-store', 'Retry-After': '300' } });
    }
  }
};
