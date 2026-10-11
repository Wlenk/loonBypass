import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { MIHOMO_FILES, PROFILE_AAD, PROFILE_PATH } from '../src/mihomo.js';

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

async function sealedFixture() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const token = Buffer.from(bytes).toString('base64url');
  const key = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = 'mode: rule\nproxies: []\nrules: [MATCH,DIRECT]\n';
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
    additionalData: new TextEncoder().encode(PROFILE_AAD) }, key, new TextEncoder().encode(plaintext));
  const envelope = { schema: 1, nonce: Buffer.from(nonce).toString('base64'),
    ciphertext: Buffer.from(encrypted).toString('base64') };
  return { token, plaintext, envelope };
}

test('owner capability decrypts a private subscription, including HEAD', async () => {
  const data = await sealedFixture();
  const assets = { fetch: async req => {
    assert.equal(new URL(req.url).pathname, PROFILE_PATH);
    assert.equal(new URL(req.url).search, '');
    return Response.json(data.envelope);
  } };
  for (const method of ['GET', 'HEAD']) {
    const response = await worker.fetch(request('/subscription/mihomo.yaml?token=' + data.token, method), { ASSETS: assets });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('Content-Type'), /application\/yaml/);
    assert.match(response.headers.get('Cache-Control'), /no-store/);
    assert.equal(await response.text(), method === 'GET' ? data.plaintext : '');
  }
});

test('missing, duplicate and wrong capabilities cannot expose the profile or ciphertext asset', async () => {
  const data = await sealedFixture();
  const env = { ASSETS: { fetch: async () => Response.json(data.envelope) } };
  for (const path of ['/subscription/mihomo.yaml', '/subscription/mihomo.yaml?token=short',
    '/subscription/mihomo.yaml?token=' + Buffer.alloc(32, 1).toString('base64url'),
    `/subscription/mihomo.yaml?token=${data.token}&token=${data.token}`, PROFILE_PATH]) {
    const response = await worker.fetch(request(path), env);
    assert.equal(response.status, 404);
    assert.ok(!(await response.text()).includes(data.plaintext));
  }
});

test('MRS assets are binary and a missing private profile reports an unavailable service', async () => {
  const binary = await worker.fetch(request('/mihomo/china-domain.mrs'), {
    ASSETS: { fetch: async () => new Response(new Uint8Array([40, 181, 47, 253])) }
  });
  assert.equal(binary.status, 200);
  assert.equal(binary.headers.get('Content-Type'), 'application/octet-stream');
  const response = await worker.fetch(request('/subscription/mihomo.yaml?token=' + 'A'.repeat(43)), {
    ASSETS: { fetch: async () => new Response('missing', { status: 404 }) }
  });
  assert.equal(response.status, 503);
});

test('health checks the linked Mihomo bundle and integrity of the encrypted private profile', async () => {
  const data = await sealedFixture();
  const body = JSON.stringify(data.envelope);
  const digest = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))).toString('hex');
  const native = { ...manifest(), mihomo: { path: '/mihomo/manifest.json', version: 'b'.repeat(64), files: 11 } };
  const converted = { schema: 1, version: native.mihomo.version, source_version: native.version,
    checked_at: native.checked_at, profile_sha256: digest, files: MIHOMO_FILES };
  const fetch = async req => {
    const path = new URL(req.url).pathname;
    if (path === '/manifest.json') return Response.json(native);
    if (path === '/mihomo/manifest.json') return Response.json(converted);
    return new Response(body);
  };
  assert.equal((await worker.fetch(request('/health'), { ASSETS: { fetch } })).status, 200);
  converted.profile_sha256 = '0'.repeat(64);
  assert.equal((await worker.fetch(request('/health'), { ASSETS: { fetch } })).status, 503);
});
