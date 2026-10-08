#!/usr/bin/env bash
set +x
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
repo_name="${LOON_GITHUB_REPO:-Wlenk/loonBypass}"
worker_base="${LOON_WORKER_URL:-https://loon-malaysia-rules.xgstudio.workers.dev}"
setup_mode="${1:-all}"
if [[ "$setup_mode" != 'all' && "$setup_mode" != '--monitor-only' ]]; then
  printf '用法：bash scripts/setup-actions.sh [--monitor-only]\n' >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  printf '无需安装 gh：推荐在 GitHub 网页填写两项 Repository secrets。\n' >&2
  printf '密钥设置：https://github.com/%s/settings/secrets/actions\n' "$repo_name" >&2
  printf '若仍使用此可选助手，Intel Mac 请安装 GitHub 官方预编译版本，避免编译 Go。\n' >&2
  exit 2
fi
if [[ ! -t 0 ]]; then
  printf '请在本机交互终端执行，密钥需要以隐藏输入方式填写。\n' >&2
  exit 2
fi

printf '先检查已部署服务和全部规则（当前版本为 9 组）。\n'
node scripts/verify-service.mjs "$worker_base"
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  gh auth login --hostname github.com --git-protocol https --web
fi
secret_names="$(gh secret list --repo "$repo_name" --json name --jq '.[].name')"
has_secret() {
  case $'\n'"$secret_names"$'\n' in
    *$'\n'"$1"$'\n'*) return 0 ;;
    *) return 1 ;;
  esac
}
set_secret() {
  printf '%s' "$2" | gh secret set "$1" --repo "$repo_name" >/dev/null
}
read_hidden() {
  read -r -s -p "$1" "$2"
  printf '\n'
}
trap 'unset cf_token bark_url cf_account' EXIT
printf '将密钥加密保存到 %s 的 Actions Secrets；不写入项目文件。\n' "$repo_name"

if ! has_secret BARK_URL; then
  read_hidden 'Bark 完整推送地址（之前那条，输入隐藏）：' bark_url
  printf '%s' "$bark_url" | node --input-type=module -e '
    let text = ""; for await (const chunk of process.stdin) text += chunk;
    try { const u = new URL(text); if (!["http:","https:"].includes(u.protocol) ||
      u.username || u.password || u.pathname === "/" || /\s/.test(text)) process.exit(2); }
    catch { process.exit(2); }
  ' || { printf 'Bark 地址格式不正确。\n' >&2; exit 2; }
  set_secret BARK_URL "$bark_url"
  unset bark_url
fi

if [[ "$setup_mode" == 'all' ]]; then
  if ! has_secret CLOUDFLARE_ACCOUNT_ID; then
    cf_account="$(npx --no-install wrangler whoami --json | node --input-type=module -e '
      let text = ""; for await (const chunk of process.stdin) text += chunk;
      const accounts = JSON.parse(text).accounts ?? [];
      if (accounts.length !== 1) process.exit(2);
      process.stdout.write(accounts[0].id);
    ')" || {
      printf '无法唯一确定账户。请从 Cloudflare 后台复制目标 Account ID。\n'
      read -r -p 'Cloudflare Account ID：' cf_account
    }
    [[ "$cf_account" =~ ^[a-fA-F0-9]{32}$ ]] || {
      printf 'Account ID 格式不正确。\n' >&2; exit 2;
    }
    set_secret CLOUDFLARE_ACCOUNT_ID "$cf_account"
    unset cf_account
  fi
  if ! has_secret CLOUDFLARE_API_TOKEN; then
    printf '创建长期 CI API Token，权限仅限目标账户的 Workers Scripts Edit / Account Settings Read。\n'
    printf '说明：https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/\n'
    read_hidden 'Cloudflare API Token（输入隐藏，不要发到聊天）：' cf_token
    [[ -n "$cf_token" && "$cf_token" != *[[:space:]]* ]] || {
      printf 'API Token 不能为空或包含空白。\n' >&2; exit 2;
    }
    set_secret CLOUDFLARE_API_TOKEN "$cf_token"
    unset cf_token
  fi
fi

gh variable set WORKER_URL --repo "$repo_name" --body "$worker_base" >/dev/null
if [[ "$setup_mode" == 'all' ]]; then
  gh variable set DEPLOY_ENABLED --repo "$repo_name" --body true >/dev/null
fi
gh variable set MONITOR_ENABLED --repo "$repo_name" --body true >/dev/null

run_and_verify() {
  local workflow_file="$1" previous_id next_id attempt
  previous_id="$(gh run list --repo "$repo_name" --workflow "$workflow_file" \
    --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
  gh workflow run "$workflow_file" --repo "$repo_name" --ref main
  next_id=''
  for attempt in {1..30}; do
    next_id="$(gh run list --repo "$repo_name" --workflow "$workflow_file" \
      --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
    if [[ -n "$next_id" && "$next_id" != "$previous_id" ]]; then break; fi
    sleep 1
  done
  if [[ -z "$next_id" || "$next_id" == "$previous_id" ]]; then
    printf '已提交工作流，请到 https://github.com/%s/actions 检查运行结果。\n' "$repo_name" >&2
    return 1
  fi
  gh run watch "$next_id" --repo "$repo_name" --interval 5 --exit-status
}

if [[ "$setup_mode" == 'all' ]]; then
  run_and_verify update.yml
fi
run_and_verify monitor.yml
printf '首次工作流已通过。外部检查每 15 分钟执行；GitHub 调度可能延迟。\n'
if [[ "$setup_mode" == 'all' ]]; then
  printf '上游同步已启用，每小时执行。\n'
fi
