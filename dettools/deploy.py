"""Deploy compiled rules from build/ to Splunk and/or Elastic (Kibana).

Run: python -m dettools.deploy --target splunk --min-status test [--dry-run]

Only rules whose status is at or above --min-status are deployed, so
experimental rules can live in the repo (and be tested) without paging anyone.

Credentials come from environment variables (set as CI secrets):
  Splunk:  SPLUNK_URL (https://host:8089), SPLUNK_TOKEN, SPLUNK_APP (default: search)
  Elastic: KIBANA_URL (https://host:5601), KIBANA_API_KEY, KIBANA_SPACE (default: default)
  Both:    DEPLOY_VERIFY_TLS (default: true)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote

import requests

from dettools.common import BUILD_DIR, STATUS_ORDER, meets_status

TIMEOUT = 30


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise SystemExit(f"Missing required environment variable {name}")
    return value


def _verify_tls() -> bool:
    return os.environ.get("DEPLOY_VERIFY_TLS", "true").lower() != "false"


def _parse_stanza(stanza: str) -> dict[str, str]:
    """Turn a savedsearches.conf stanza into REST parameters (minus the header)."""
    params = {}
    for line in stanza.splitlines()[1:]:
        if " = " in line:
            key, value = line.split(" = ", 1)
            params[key] = value
    return params


def deploy_splunk(rules: list[dict], dry_run: bool) -> int:
    if dry_run:
        for r in rules:
            print(f"[dry-run] splunk upsert: {r['name']}")
        return 0

    base = _env("SPLUNK_URL").rstrip("/")
    app = os.environ.get("SPLUNK_APP", "search")
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {_env('SPLUNK_TOKEN')}"
    session.verify = _verify_tls()
    collection = f"{base}/servicesNS/nobody/{quote(app)}/saved/searches"

    failures = 0
    for r in rules:
        params = _parse_stanza(r["splunk"]["stanza"])
        entity = f"{collection}/{quote(r['name'], safe='')}"
        exists = session.get(entity, params={"output_mode": "json"}, timeout=TIMEOUT).status_code == 200
        if exists:
            resp = session.post(entity, data={**params, "output_mode": "json"}, timeout=TIMEOUT)
        else:
            resp = session.post(collection, data={"name": r["name"], **params, "output_mode": "json"}, timeout=TIMEOUT)
        action = "updated" if exists else "created"
        if resp.ok:
            print(f"splunk {action}: {r['name']}")
        else:
            failures += 1
            print(f"splunk FAILED ({resp.status_code}) {r['name']}: {resp.text[:300]}")
    return 1 if failures else 0


def deploy_elastic(rules: list[dict], build_dir: Path, dry_run: bool) -> int:
    wanted = {rid for r in rules for rid in r["elastic_rule_ids"]}
    lines = [
        line for line in (build_dir / "elastic" / "rules.ndjson").read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line)["rule_id"] in wanted
    ]
    if dry_run:
        for line in lines:
            print(f"[dry-run] elastic import: {json.loads(line)['name']}")
        return 0
    if not lines:
        print("elastic: nothing to deploy")
        return 0

    base = _env("KIBANA_URL").rstrip("/")
    space = os.environ.get("KIBANA_SPACE", "default")
    prefix = "" if space == "default" else f"/s/{quote(space)}"
    resp = requests.post(
        f"{base}{prefix}/api/detection_engine/rules/_import",
        params={"overwrite": "true"},
        headers={"kbn-xsrf": "true", "Authorization": f"ApiKey {_env('KIBANA_API_KEY')}"},
        files={"file": ("rules.ndjson", "\n".join(lines) + "\n", "application/x-ndjson")},
        timeout=TIMEOUT,
        verify=_verify_tls(),
    )
    if not resp.ok:
        print(f"elastic FAILED ({resp.status_code}): {resp.text[:500]}")
        return 1
    body = resp.json()
    print(f"elastic import: success_count={body.get('success_count')} errors={len(body.get('errors', []))}")
    for err in body.get("errors", []):
        print(f"  - {err.get('rule_id')}: {err.get('error', {}).get('message')}")
    return 1 if body.get("errors") else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", choices=["splunk", "elastic", "all"], required=True)
    parser.add_argument("--min-status", choices=STATUS_ORDER, default="test")
    parser.add_argument("--build-dir", type=Path, default=BUILD_DIR)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    manifest_path = args.build_dir / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"{manifest_path} not found; run `python -m dettools.convert` first")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rules = [r for r in manifest if meets_status(r["status"], args.min_status)]
    skipped = [r["title"] for r in manifest if r not in rules]
    print(f"Deploying {len(rules)} rule(s) with status >= {args.min_status}; skipping {len(skipped)}: {skipped}")

    rc = 0
    if args.target in ("splunk", "all"):
        rc |= deploy_splunk(rules, args.dry_run)
    if args.target in ("elastic", "all"):
        rc |= deploy_elastic(rules, args.build_dir, args.dry_run)
    return rc


if __name__ == "__main__":
    sys.exit(main())
