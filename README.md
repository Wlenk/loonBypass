# Loon 马来西亚回国规则服务

国内默认经家庭 Mac mini；各平台可独立选择节点或 DIRECT。此项目只有公开规则，
不包含用户 Loon 节点、密码、证书指纹、订阅地址或通知密钥。

## 规则顺序

Loon 的本地规则：节点入口 / 内网 / Apple 推送直连 → 可识别通话 → 广告规则。
远程规则订阅必须依次为：netease-music、tencent-games、tiktok、douyin、netease-other、
tencent、alibaba、china。FINAL 为海外默认（DIRECT）。不要在远程平台规则前放本地 qq.com、
163.com 等平台总域名或 GEOIP,CN，否则会覆盖细分规则。

每个文件使用 Loon 原生文本规则，不是 mihomo 的 mrs/dat，也不需要 domain-set 参数。
腾讯游戏列表同时包括 Riot 手游相关域名。共享 CDN、纯 IP 通话及动态 UDP 不能保证按 App
完全区分；STUN 是打洞流量，也可能来自游戏。微信 UDP 域名例外须由 Loon 本地 AND 规则处理。

## 发布与更新

1. 建立公开 GitHub 仓库，上传本项目；不要上传私人 .lcf。
2. 将项目解压到电脑上持久保存的目录，再使用 Cloudflare Workers 免费方案部署：
   `npm ci --ignore-scripts` 后执行 `npx wrangler deploy`。已登录 Wrangler 时无需重复登录。
3. 仓库 Actions secrets 设置 `CLOUDFLARE_API_TOKEN`（只授权目标账户 Workers 编辑）、
   `CLOUDFLARE_ACCOUNT_ID`、`BARK_URL`；变量 `WORKER_URL` 填真实 Worker 地址。
   密钥必须用安全登录/手动输入流程配置，不能写在代码或 README 中。
4. 配齐密钥后设置仓库变量 DEPLOY_ENABLED=true、MONITOR_ENABLED=true；然后手动运行
   Update verified rules 和 External Worker monitoring，验证首次部署及推送。
5. 已配置每小时同步上游，每 15 分钟外部检查；GitHub 定时任务可能延迟，不能保证即时告警。

Workers 免费方案每次请求及定时执行均只有 10 ms CPU，所以大规模转换由 GitHub Actions 完成。
访问规则时只分发部署内已校验的静态文件，不临时依赖 GitHub、不使用 KV 的非原子指针更新。
成功部署以完整 Worker 版本为单位；部署前失败继续保留上一版。规则更新并非每次请求实时重建。

## 故障保护

- 上游超时、空列表、非原生规则、IP 错误及规则数量下降超过 20%：停止更新，保留旧部署。
- Worker 异常：返回 503，不能返回空的成功规则文件。
- 外部监控检查健康状态、72 小时更新超时、8 个文件的长度与 SHA-256；服务完全宕机也能检查。
- 故障通知每条监控通道最多每 6 小时重复一次；恢复通知一次。两条通道分别记录事件。
- GitHub 镜像在 `public/rules/`；必要时手动改用 raw.githubusercontent.com 的仓库镜像地址。
  Loon 是否保留下载缓存取决于客户端行为，不能声称它会自动切换镜像；独立离线配置最可靠。
- 本项目内置完整公开规则快照。版本可在 Cloudflare 后台回滚。监控依赖 GitHub 与通知服务器，
  两者同时故障时无法保证送达。

## 验证

`python -m unittest discover -s tests -p 'test_*.py'` 和 `npm test`。
没有对实际 iOS Loon 导入、家庭节点连通性或游戏延迟进行测试。

工具链固定为 Wrangler 4.148.0，提供 package-lock.json。由于间接依赖 sharp 的
GHSA-wq5f-xc86-pv6w，覆盖为修复版本 0.35.5；不使用 npm audit fix --force。
本地检查包含 npm audit、无安装脚本模式下的 Wrangler deploy --dry-run 和 Worker 测试。

## 已部署地址与启用助手

部署地址：<https://loon-malaysia-rules.xgstudio.workers.dev>。
部署成功后，还需分别确认规则能够下载和 Actions 已配置；本地 Wrangler 登录不会自动
为 GitHub Actions 提供长期部署凭据。

在 Mac 项目目录执行 `node scripts/verify-service.mjs`，检查健康状态和全部 8 个文件的
SHA-256。如果返回 Cloudflare 403 / 1010，需要在自己的账户检查访问限制；不要把访问
拦截直接判定为 Worker panic。

配置助手：先安装 GitHub CLI（`brew install gh`），然后执行
`bash scripts/setup-actions.sh`。助手先验证服务，再复用已有 Secrets，隐藏输入缺少的
Bark 地址和 Cloudflare API Token，自动读取唯一的 Account ID。它仅通过 stdin 将密钥
交给 GitHub CLI 加密保存；不会写入代码或打印密钥。随后设置启用变量、运行并等待首次
更新与监控工作流成功。只有运行通过才可认为自动任务已验证。

如果暂时只想启用外部监控，可执行 `bash scripts/setup-actions.sh --monitor-only`；
该模式只需要 Bark 地址，不设置 Cloudflare 部署密钥或开启自动更新。已有 Secrets 不会被
助手覆盖；更换失效密钥应在仓库设置或 GitHub CLI 中主动更新。

## 来源及归属

主要来源：[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) 与
[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)。完整来源 URL 保存在
`public/manifest.json`。编译器是自定义代码；上游数据及其权利归原项目和对应贡献者所有，
公开发布前保留这些来源和上游适用的许可声明。
