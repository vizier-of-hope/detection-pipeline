# The detection-pipeline Docker image

A single image that runs the whole detection-as-code pipeline — validation and multi-SIEM
compilation — reproducibly, with the exact pinned toolchain (`requirements.txt`). Use it in CI
and locally so results never depend on a developer's machine.

What it runs (the "gate suite", in order; stops at the first failure):

1. `yamllint` — YAML style, enforces LF line endings
2. `sigma check` — valid Sigma syntax + real ATT&CK tags
3. `dettools.validate` — team policy (required fields, UUID, fixture present, unique id/title)
4. `pytest` — rule logic (TP/TN fixtures) and the tooling
5. `dettools.convert` — compile every rule to each SIEM target, writing `build/`

## Build

From the repo root (where the `Dockerfile` is):

```bash
docker build -t detection-pipeline .
```

Rebuild after changing dependencies or tooling. Editing only rules/fixtures does not require a
rebuild if you mount the repo (see "Validate local edits" below).

## Use it

### 1. Run the full gate suite (what CI does)

```bash
docker run --rm detection-pipeline
```

Exit code 0 = every gate passed; non-zero = something failed (the output names which gate).
`--rm` deletes the container afterwards.

### 2. Validate your local edits and get the compiled queries out

Mount your working copy over `/work` so the container validates the rules you just edited and
writes `build/` back to the host:

```bash
# macOS/Linux/Git-Bash
docker run --rm -v "$PWD:/work" detection-pipeline

# Windows PowerShell
docker run --rm -v "${PWD}:/work" detection-pipeline
```

Afterwards the compiled per-SIEM queries are on the host under `build/queries/<target>/`, plus
`build/coverage.md`, `build/manifest.json`, `build/splunk/`, and `build/elastic/`.

### 3. Run a single step (override the command)

```bash
docker run --rm detection-pipeline pytest -q
docker run --rm detection-pipeline sigma check --fail-on-issues rules
docker run --rm -v "$PWD:/work" detection-pipeline \
  python -m dettools.translate rules/azure/signin/signin_azure_aitm_token_theft_risk.yml
docker run --rm -v "$PWD:/work" detection-pipeline python -m dettools.convert
```

### 4. Interactive shell (poke around inside the image)

```bash
docker run --rm -it detection-pipeline bash
```

## Deploy from the image (optional)

The image also carries `dettools.deploy`. Pass your SIEM credentials as environment variables
and mount the build output. Deployment is a separate, deliberate step — never part of the gate
suite.

```bash
docker run --rm -v "$PWD:/work" \
  -e SPLUNK_URL -e SPLUNK_TOKEN \
  -e KIBANA_URL -e KIBANA_API_KEY \
  detection-pipeline \
  python -m dettools.deploy --target all --min-status test --dry-run
```

Drop `--dry-run` to actually deploy. Keep secrets in your shell/CI secret store, never in the
image or the repo.

## In CI (GitHub Actions example)

```yaml
# .github/workflows/detections.yml
jobs:
  gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t detection-pipeline .
      - run: docker run --rm detection-pipeline        # fails the job if any gate fails
```

On the default branch you can add a second step that runs `dettools.deploy` with repository
secrets to ship rules at or above a chosen status.

## Notes

- The image bakes in a copy of the repo at build time, so `docker run` with no mount validates
  exactly what was built — ideal for CI. Mount the repo (option 2) only for live local editing.
- `build/`, `.venv/`, caches and `.git/` are excluded from the image via `.dockerignore`.
- For an end-user (single-SIEM) setup you can trim `dettools/targets.py` to just your SIEM so
  the `convert` step is faster and only emits the artifacts you deploy.
