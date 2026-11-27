# kvault

Fetches secrets from a KVault instance using the job's GitHub OIDC token, masks each value in the log, and exports it as an environment variable for later steps in the job.

The action calls KVault's `GET /api/oidc/secrets/<name>`, its route for CI OIDC tokens (KVault v0.14.0 or later; `kvault/v1.0.0` used the older `/api/gh-oidc/` path, which KVault still serves). It holds no credentials of its own: access is decided by the KVault instance's trust policies.

## Usage

```yaml
permissions:
  contents: read
  id-token: write   # required to request the OIDC token

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: get-everything-cloud/github-actions/kvault@kvault/v1.0.0
        with:
          url: https://vault.example.com
          audience: kvault-example
          secrets: |
            builds-rclone=RCLONE_CONFIG
            builds-apt-rpm-gpg=GPG_PRIVATE_KEY
      - run: ./release.sh   # reads $RCLONE_CONFIG and $GPG_PRIVATE_KEY
```

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `url` | yes | Base URL of the KVault instance. Must be `https`. |
| `audience` | yes | OIDC audience to request. Must equal the instance's `GH_OIDC_AUD` setting. |
| `secrets` | yes | One `<secret-name>=<ENV_VAR>` mapping per line. Blank lines and lines starting with `#` are ignored. |

Environment variable names must match `[A-Za-z_][A-Za-z0-9_]*`, must not start with `GITHUB_`, `RUNNER_` or `ACTIONS_`, and may each be mapped once. A secret name may be mapped to several variables; it is fetched once.

The action has no outputs. Values are passed only through `$GITHUB_ENV`.

## Behaviour

- All secrets are fetched before any variable is exported. If any fetch fails, the step fails and no variables are set.
- Every value is registered with `::add-mask::`. Multi-line values (keys, PEM files) are also masked line by line, because the runner masks per log line. Lines shorter than 4 characters are not masked on their own.
- The OIDC token is masked too.

## KVault requirements

- `GH_OIDC_AUD` must be set on the instance. Without it the route returns 503.
- A trust policy must match the job's token: the repository's numeric id (`gh api repos/<owner>/<repo> --jq .id`) plus the `ref` and/or `environment` the policy names. Its `allowedSecretNames` must list each secret.
- Secrets with an IP restriction are always refused on this route. Fetch those with a Service Token or machine key.
- If Cloudflare Access protects the instance, `/api/oidc/*` needs an Access Bypass policy. A runner has no Access identity, so Access would otherwise redirect or block the request before it reaches KVault.

## Errors

| Response | Error message points to |
| --- | --- |
| No `id-token: write` | The missing job permission. |
| 401 | `audience` not matching `GH_OIDC_AUD`. |
| 403 | The token's repository id, ref and environment, the trust policy's `allowedSecretNames`, or an IP restriction. |
| 404 | No secret with that name. |
| 503 | GitHub OIDC disabled on the instance (`GH_OIDC_AUD` unset). |
| Redirect or non-JSON | Cloudflare Access in front of `/api/oidc/*`. |

## Runtime

Node 24, no dependencies.
