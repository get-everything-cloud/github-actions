# get-everything-cloud / github-actions

Reusable GitHub Actions maintained by get-everything-cloud. Each action lives in its own folder, has its own README, and is versioned on its own, so you can adopt one without taking on the others.

## Available actions

| Action | What it does |
| --- | --- |
| [`kvault`](kvault/) | Fetches secrets from a [KVault](#kvault) instance using the job's GitHub OIDC token, masks them in the log and exports them as environment variables. No long-lived credentials are stored in GitHub. |

## Quick start

Reference an action by its folder and a tag:

```yaml
permissions:
  contents: read
  id-token: write   # needed by kvault

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: get-everything-cloud/github-actions/kvault@kvault/v1.0.0
        with:
          url: https://vault.example.com
          audience: kvault-example
          secrets: |
            deploy-token=DEPLOY_TOKEN
      - run: ./deploy.sh   # reads $DEPLOY_TOKEN
```

Each action's README lists its inputs, requirements and error messages.

## Versioning

Tags are per action, in the form `<action>/vX.Y.Z`:

```
kvault/v1.0.0
kvault/v1.1.0
```

A single repo-wide tag such as `v1` would release every action at once, so a change to one action would look like a new version of all of them. Per-action tags keep each action's history separate.

Version numbers follow [Semantic Versioning](https://semver.org/): a major bump means a breaking change to inputs or behaviour.

## Pinning

For workflows that handle secrets, pin to a full commit SHA rather than a tag, because a tag can be moved:

```yaml
- uses: get-everything-cloud/github-actions/kvault@<commit-sha> # kvault/v1.0.0
```

Dependabot and Renovate can keep SHA pins up to date.

## Design principles

- **No dependencies.** Actions are plain Node scripts using only the Node standard library, so there is no `node_modules` or bundled third-party code to audit.
- **No stored credentials.** Where an action authenticates to a service, it uses the job's short-lived GitHub OIDC token.
- **Fail clearly.** Errors say what was refused and what to check, without printing secret values.

## KVault

KVault is a self-hosted secrets manager. The `kvault` action works with any KVault instance that has GitHub Actions OIDC enabled and a trust policy for your repository. See the [action's README](kvault/) for what the instance needs.

## Development

Requires Node 24.

```sh
node --test
```

Tests run against local mock servers only and make no external network calls. The `test` workflow runs them on every push to `main` and on every pull request.

### Adding an action

1. Create a folder named after the action, containing `action.yml`, the code, a `README.md` and a `test/` folder.
2. Add a row to the table under [Available actions](#available-actions).
3. Release it with a tag of the form `<action>/v1.0.0`.

## Security

Please report vulnerabilities privately through GitHub's **Security → Report a vulnerability** on this repository rather than in a public issue.
