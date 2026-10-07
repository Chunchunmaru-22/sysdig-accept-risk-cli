# sysdig-accept-risk-cli

Interactive Python CLI that creates many Sysdig Secure accepted risk exceptions in one guided run, instead of one at a time in the UI. It always shows the full plan and asks you to type `CREATE` before changing anything -- nothing is written unless you confirm.

## Requirements

- Python 3.10+
- The `requests` package
- A Sysdig Secure API token that can read vulnerabilities and create accepted risks

## Setup

```bash
git clone https://github.com/Chunchunmaru-22/sysdig-accept-risk-cli.git
cd sysdig-accept-risk-cli
python3 -m venv venv
source venv/bin/activate          # on Windows: venv\Scripts\activate
python3 -m pip install -r requirements.txt
```

Re-run `source venv/bin/activate` each time you open a new terminal.

## Usage

Set your token once per terminal session (recommended over `--token-file`, since it avoids leaving a token file on disk):

```bash
export SYSDIG_SECURE_API_TOKEN=...
python3 sysdig_accept_risk.py --base-url https://app.us4.sysdig.com
```

Use the URL you open in your browser to reach Sysdig -- any SaaS region, or on-prem. The tool detects the matching API endpoint on its own.

It walks you through source, image, severities, package(s), and scope, then shows the full plan before asking you to type `CREATE`. Anything else cancels with no changes made.

## Options

| Option | Description |
|---|---|
| `--base-url` | Tenant URL you use in your browser (SaaS or on-prem) |
| `--token-file` | File containing only your API token |
| `--token` | API token directly (discouraged: visible in shell history) |
| `--ca-bundle` | Custom CA certificate, for on-prem tenants with an internal CA |
| `--proxy` | HTTP(S) proxy URL |
| `--insecure-skip-tls-verify` | Disable TLS verification (lab/troubleshooting only) |
| `--report-dir` | Where to save the report (default: `./reports`) |

## API endpoints used

All paths are relative to your tenant's API host.

| Method | Path | Purpose |
|---|---|---|
| GET | `/secure/vulnerability/v1beta1/accepted-risks` | Connectivity check; list existing records for duplicate detection |
| POST | `/secure/vulnerability/v1beta1/accepted-risks` | Create an accepted risk |
| GET | `/secure/vulnerability/{v1\|v1beta1}/runtime-results` | List runtime image results |
| GET | `/secure/vulnerability/{v1\|v1beta1}/registry-results` | List registry image results |
| GET | `/secure/vulnerability/{v1\|v1beta1}/pipeline-results` | List pipeline image results |
| GET | `/secure/vulnerability/{v1\|v1beta1}/results/{resultId}` | Fetch a result's packages and CVEs |

The only write operation is the POST that creates an accepted risk, and it requires explicit confirmation. The tool never deletes or modifies existing records.

## Good to know

- One rule is created per CVE, not per package -- the plan always shows the real total first.
- Source, image and package are only used to find and select the CVEs. With **Global** or **Image** scope, the exceptions are created under the scope you choose, regardless of the source, image or package the CVEs came from. With **Package** scope, each rule is also restricted to the package it was selected from.
- Existing accepted risks are checked first, so re-running after a partial failure is safe (duplicates are skipped, not recreated).
- On-prem with an internal CA: add `--ca-bundle /path/to/ca.pem`. Behind a proxy: `--proxy`.

## Troubleshooting

- `ModuleNotFoundError: No module named 'requests'` -- run `source venv/bin/activate` first.
- `externally-managed-environment` -- you installed outside the venv; redo the setup above.
- Any other error explains itself in plain English. For unexpected failures, details are saved to `<report-dir>/error.log`.

## Disclaimer

Provided as-is, without warranty. Review the plan carefully before typing `CREATE`.
