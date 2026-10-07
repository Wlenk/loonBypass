import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const RULESETS = [
  'netease-music', 'tencent-games', 'tiktok', 'douyin',
  'netease-other', 'tencent', 'alibaba', 'china',
];

export async function verifyService(base, { fetchImpl = fetch, now = Date.now() } = {}) {
  const origin = new URL(base);
  if (origin.protocol !== 'https:' || origin.username || origin.password ||
      origin.search || origin.hash || origin.pathname !== '/') {
    throw new Error('Worker 地址必须是没有密码、路径或查询参数的 HTTPS 地址');
  }
  async function get(path) {
    const response = await fetchImpl(new URL(path, origin), {
      redirect: 'error', signal: AbortSignal.timeout(35_000),
    });
    if (!response.ok) {
      const hint = response.status === 403 ? '；请检查 Cloudflare 的访问限制' : '';
      throw new Error(`${path}: HTTP ${response.status}${hint}`);
    }
    return response;
  }
  const [health, manifest] = await Promise.all([
    get('/health').then(response => response.json()),
    get('/manifest.json').then(response => response.json()),
  ]);
  const age = now - Date.parse(manifest.checked_at);
  if (!health.ok || health.version !== manifest.version || manifest.schema !== 1 ||
      !Number.isFinite(age) || age > 72 * 3_600_000 || age < -300_000 ||
      Object.keys(manifest.files ?? {}).sort().join() !== [...RULESETS].sort().join()) {
    throw new Error('健康状态、版本或规则更新时间不符合要求');
  }
  const verified = await Promise.all(RULESETS.map(async name => {
    const entry = manifest.files[name];
    if (entry.path !== `/rules/${name}.list` || !Number.isInteger(entry.bytes) ||
        entry.bytes < 1 || !Number.isInteger(entry.count) || entry.count < 1 ||
        !/^[a-f0-9]{64}$/.test(entry.sha256 ?? '')) {
      throw new Error(`${name}: 清单内容无效`);
    }
    const response = await get(entry.path);
    const body = Buffer.from(await response.arrayBuffer());
    if (body.length !== entry.bytes ||
        createHash('sha256').update(body).digest('hex') !== entry.sha256) {
      throw new Error(`${name}: 文件长度或 SHA-256 校验失败`);
    }
    return { name, count: entry.count, bytes: body.length };
  }));
  return { ok: true, version: manifest.version, checked_at: manifest.checked_at, rulesets: verified };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await verifyService(process.argv[2] ??
      'https://loon-malaysia-rules.xgstudio.workers.dev');
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`规则服务检查失败：${error.message}`);
    process.exitCode = 1;
  }
}
