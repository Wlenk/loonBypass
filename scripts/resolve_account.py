"""Resolve one authorized Cloudflare account without exposing deployment credentials."""
import json
import os
import re
import sys
import urllib.request


def resolve_account_id(token, configured_id="", opener=urllib.request.urlopen):
    if configured_id:
        if not re.fullmatch(r"[a-fA-F0-9]{32}", configured_id):
            raise RuntimeError("CLOUDFLARE_ACCOUNT_ID must be a 32-character account ID")
        return configured_id
    if not token:
        raise RuntimeError("CLOUDFLARE_API_TOKEN is missing")
    request = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/accounts?per_page=50",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    try:
        with opener(request, timeout=30) as response:
            payload = json.load(response)
    except Exception:
        raise RuntimeError("Cloudflare account lookup failed; check token permissions and connectivity") from None
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise RuntimeError("Cloudflare did not authorize the account lookup")
    accounts = payload.get("result")
    if not isinstance(accounts, list) or len(accounts) != 1:
        raise RuntimeError("Scope the token to one account, or add CLOUDFLARE_ACCOUNT_ID as a repository secret")
    account_id = accounts[0].get("id") if isinstance(accounts[0], dict) else None
    if not isinstance(account_id, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", account_id):
        raise RuntimeError("Cloudflare returned an invalid account ID")
    return account_id


def main():
    account_id = resolve_account_id(
        os.environ.get("CLOUDFLARE_API_TOKEN", ""),
        os.environ.get("CLOUDFLARE_ACCOUNT_ID", ""),
    )
    target = os.environ.get("GITHUB_ENV")
    if not target:
        raise RuntimeError("This helper must run inside GitHub Actions")
    with open(target, "a", encoding="utf-8") as output:
        output.write("CLOUDFLARE_ACCOUNT_ID=" + account_id + "\n")
    print("Resolved the target Cloudflare account; credentials remain private.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
