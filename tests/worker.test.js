import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const request = (path, method = 'GET') => new Request('https://rules.example' + path, { method });
const names = ['netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn',
  'netease-other', 'tencent', 'alibaba', 'china'];
const manifest = () => ({ schema: 1, version: 'verified', checked_at: new Date().toISOString(),
  files: Object.fromEntries(names.map(name => [name, {}])) });

test('serves verified assets without contacting upstreams', async () => {
  for (const name of ['tiktok', 'china-cdn']) {
    const response = await worker.fetch(request(`/rules/${name}.list`), {
      ASSETS: { fetch: async () => new Response('DOMAIN-SUFFIX,example.com\n') }
    });
    assert.equal(response.status, 200);
    assert.match(await response.text(), /example.com/);
    assert.match(response.headers.get('Content-Type'), /text\/plain/);
  }
});
test('asset exception and missing asset never become empty 200 rules', async () => {
  for (const fetch of [async () => { throw Error('outage'); }, async () => new Response('', { status: 404 })]) {
    const response = await worker.fetch(request('/rules/china.list'), { ASSETS: { fetch } });
    assert.equal(response.status, 503);
    assert.ok((await response.text()).length > 0);
  }
});
test('health rejects stale, incomplete and corrupt manifests', async () => {
  for (const data of [{ ...manifest(), checked_at: '2020-01-01T00:00:00Z' },
    { ...manifest(), files: {} }, { ...manifest(), checked_at: 'invalid' },
    { ...manifest(), files: Object.fromEntries(names.map(name => [name === 'china-cdn' ? 'wrong' : name, {}])) }]) {
    const response = await worker.fetch(request('/health'), { ASSETS: { fetch: async () => Response.json(data) } });
    assert.equal(response.status, 503);
    assert.equal((await response.json()).ok, false);
  }
});
test('valid health and conditional downloads work', async () => {
  const healthy = await worker.fetch(request('/health'), { ASSETS: { fetch: async () => Response.json(manifest()) } });
  assert.equal(healthy.status, 200);
  const cached = await worker.fetch(request('/rules/china.list'), {
    ASSETS: { fetch: async () => new Response(null, { status: 304 }) }
  });
  assert.equal(cached.status, 304);
});
test('unrecognized paths and writes are rejected', async () => {
  assert.equal((await worker.fetch(request('/rules/not-a-rule.list'), {})).status, 404);
  assert.equal((await worker.fetch(request('/rules/china.list', 'POST'), {})).status, 405);
});
