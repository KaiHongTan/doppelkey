# Releasing

Maintainer notes. Pushing a `v*` tag runs [`release.yml`](../.github/workflows/release.yml), which does the following:

1. checks that the tag matches every package version;
2. builds `doppelkey` and `doppelkeyd` for Linux and macOS (x64 and arm64), each bundled with the shims;
3. publishes a GitHub release with the archives, `SHA256SUMS` and `install.sh`;
4. publishes to npm, PyPI and RubyGems.

Every publish step skips a version that is already on the registry, so you can re-run a failed run.

## One-time setup

| Where | What |
| --- | --- |
| npmjs.com | Create the free organization **`doppelkey`**, which owns the `@doppelkey/cli-*` binary packages. |
| npmjs.com | For the first release only, create a granular access token with publish rights, and save it as the repository secret `NPM_TOKEN`. |
| pypi.org | Add a pending trusted publisher: project `doppelkey`, owner `KaiHongTan`, repository `doppelkey`, workflow `release.yml`, environment `pypi`. |
| rubygems.org | Add a pending trusted publisher: gem `doppelkey`, repository `KaiHongTan/doppelkey`, workflow `release.yml`, environment `rubygems`. |
| GitHub | Optional: protect the `pypi` and `rubygems` environments with required reviewers. |

### After the first release

npm can't trust-publish a package that doesn't exist yet, which is why the first release needs the token.

Once the first release is out, add a trusted publisher (workflow `release.yml`) to each of the five npm packages: `doppelkey` and `@doppelkey/cli-{linux-x64,linux-arm64,darwin-x64,darwin-arm64}`. Then delete the `NPM_TOKEN` secret. The workflow then authenticates with GitHub's OIDC token.

## Releasing a version

```bash
sh packaging/set-version.sh 0.2.0
# In CHANGELOG.md, rename [Unreleased] to [0.2.0] - YYYY-MM-DD
git commit -am "Release 0.2.0"
git tag v0.2.0
git push origin main v0.2.0
```

A tag with a pre-release suffix, such as `v0.2.0-rc.1`, publishes to npm under the `next` dist-tag rather than `latest`.

## Optional

- **macOS signing.** An Apple Developer ID gives the keeper the hardened-runtime memory protection described in [SECURITY.md](../SECURITY.md). Without one, macOS builds ship unsigned, and that protection is missing. To enable signing, add these repository secrets: `APPLE_CERT_P12` (base64), `APPLE_CERT_PASSWORD`, `APPLE_TEAM_ID`, and a notary API key as `APPLE_NOTARY_KEY`, `APPLE_NOTARY_KEY_ID` and `APPLE_NOTARY_ISSUER`. The signing step runs only when they are set.
- **Homebrew.** Create `KaiHongTan/homebrew-tap` and copy in [`packaging/homebrew/doppelkey.rb`](../packaging/homebrew/doppelkey.rb), filled in with the checksums from the release's `SHA256SUMS`. Users then run `brew install KaiHongTan/tap/doppelkey`.
