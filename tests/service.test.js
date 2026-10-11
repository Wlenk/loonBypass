import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { verifyService } from '../scripts/verify-service.mjs';
import { MIHOMO_FILES } from '../src/mihomo.js';

const names = ['netease-music', 'tencent-games', 'tiktok', 'douyin', 'china-cdn',
  'netease-other', 'tencent', 'alibaba', 'china'];

function fixture() {
  const body = Buffer.from('DOMAIN-SUFFIX,example.com\n');
  const manifest = {
    schema: 1, version: 'a'.repeat(64), checked_at: new Date().toISOString(),
    files: Object.fromEntries(names.map(name => [name, {
      path: `/rules/${name}.list`, count: 1, bytes: body.length,
      sha256: createHash('sha256').update(body).digest('hex'),
    }])),
  };
  const requests = [];
  async function fetchImpl(url, options) {
    requests.push({ path: url.pathname, options });
    if (url.pathname === '/health') return Response.json({ ok: true, version: manifest.version });
    if (url.pathname === '/manifest.json') return Response.json(manifest);
    return new Response(body);
  }
  return { manifest, fetchImpl, requests };
}

test('service verification downloads and hashes all nine rulesets', async () => {
  const data = fixture();
  const checked = await verifyService('https://rules.example', data);
  assert.equal(checked.ok, true);
  assert.equal(checked.rulesets.length, 9);
  assert.equal(data.requests.length, 11);
  assert.ok(data.requests.every(item => item.options.redirect === 'error'));
});

test('a complete previous deployment is monitored during an upgrade but cannot verify a new deployment', async () => {
  const data = fixture();
  delete data.manifest.files['china-cdn'];
  const checked = await verifyService('https://rules.example', data);
  assert.equal(checked.rulesets.length, 8);
  await assert.rejects(verifyService('https://rules.example', {
    ...data, expectedVersion: data.manifest.version,
  }), /不符合要求/);
});

test('fresh older deployments cannot pass post-deployment verification', async () => {
  const data = fixture();
  await assert.rejects(verifyService('https://rules.example', {
    ...data, expectedVersion: 'b'.repeat(64),
  }), /公开版本与本次部署版本不一致/);
});

test('stale, future, incomplete and malformed manifests are rejected', async () => {
  for (const change of [
    data => { data.checked_at = new Date(Date.now() - 73 * 3_600_000).toISOString(); },
    data => { data.checked_at = new Date(Date.now() + 360_000).toISOString(); },
    data => { delete data.files.china; },
    data => { data.files.extra = data.files.china; },
    data => { data.version = 'invalid'; },
  ]) {
    const data = fixture();
    change(data.manifest);
    await assert.rejects(verifyService('https://rules.example', data), /不符合要求/);
  }
});

test('changed bytes, hashes, paths and counts fail verification', async () => {
  for (const change of [
    item => { item.bytes = 1; },
    item => { item.sha256 = '0'.repeat(64); },
    item => { item.path = 'https://private.example/private-token'; },
    item => { item.count = 0; },
  ]) {
    const data = fixture();
    change(data.manifest.files.china);
    await assert.rejects(verifyService('https://rules.example', data), error => {
      assert.ok(!error.message.includes('private-token'));
      return /china:/.test(error.message);
    });
  }
});

test('Cloudflare rejection reports its code without including response contents', async () => {
  await assert.rejects(verifyService('https://rules.example', {
    fetchImpl: async () => new Response('error code: 1010 private-token', { status: 403 }),
  }), error => {
    assert.match(error.message, /HTTP 403.*Cloudflare error 1010/);
    assert.ok(!error.message.includes('private-token'));
    return true;
  });
});

test('invalid JSON responses and connection failures cannot leak response contents', async () => {
  for (const fetchImpl of [
    async () => new Response('private-token'),
    async () => { throw new Error('https://private.example/private-token'); },
  ]) {
    await assert.rejects(verifyService('https://rules.example', { fetchImpl }), error => {
      assert.ok(!error.message.includes('private-token'));
      return true;
    });
  }
});

test('origins with credentials, paths or queries are rejected before fetching', async () => {
  for (const url of ['http://rules.example', 'https://name:private-token@rules.example',
    'https://rules.example/path', 'https://rules.example?token=private-token']) {
    await assert.rejects(verifyService(url, { fetchImpl: async () => assert.fail() }), /HTTPS 地址/);
  }
});

function mihomoFixture() {
  const data = fixture();
  const binary = Buffer.from([40, 181, 47, 253, 1, 2, 3]);
  data.manifest.mihomo = { path: '/mihomo/manifest.json', version: 'b'.repeat(64), files: 11 };
  const converted = { schema: 1, version: data.manifest.mihomo.version,
    source_version: data.manifest.version, checked_at: data.manifest.checked_at, profile_sha256: 'c'.repeat(64),
    files: Object.fromEntries(Object.entries(MIHOMO_FILES).map(([name, format]) => [name, {
      ...format, count: 1, bytes: binary.length, sha256: createHash('sha256').update(binary).digest('hex'),
    }])) };
  const oldFetch = data.fetchImpl;
  data.fetchImpl = async (url, options) => {
    if (url.pathname === '/health') return Response.json({ ok: true, version: data.manifest.version,
      mihomo_version: converted.version, mihomo_rulesets: 11 });
    if (url.pathname === '/mihomo/manifest.json') return Response.json(converted);
    if (url.pathname.startsWith('/mihomo/')) return new Response(binary);
    return oldFetch(url, options);
  };
  return { ...data, converted };
}

test('Mihomo verification hashes all eleven files including binary MRS assets', async () => {
  const data = mihomoFixture();
  const checked = await verifyService('https://rules.example', { ...data, expectedVersion: 'a'.repeat(64),
    expectedMihomoVersion: 'b'.repeat(64) });
  assert.equal(checked.rulesets.length, 9);
  assert.equal(checked.mihomo_rulesets.length, 11);
});

test('old, unlinked, missing or corrupt Mihomo files cannot pass post-deployment checks', async () => {
  for (const modify of [
    data => { data.converted.source_version = 'c'.repeat(64); },
    data => { delete data.converted.files['china-domain']; },
    data => { data.converted.files['china-ipcidr'].sha256 = '0'.repeat(64); },
    data => { data.converted.files['china-domain'].format = 'text'; },
    data => { data.converted.checked_at = '2020-01-01'; },
    data => { data.manifest.mihomo.version = 'c'.repeat(64); },
  ]) {
    const data = mihomoFixture();
    modify(data);
    await assert.rejects(verifyService('https://rules.example', data), /Mihomo/);
  }
  await assert.rejects(verifyService('https://rules.example', {
    ...fixture(), expectedMihomoVersion: 'b'.repeat(64),
  }), /Mihomo/);
  await assert.rejects(verifyService('https://rules.example', {
    ...mihomoFixture(), expectedMihomoVersion: 'c'.repeat(64),
  }), /公开版本与本次部署版本不一致/);
});
