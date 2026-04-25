# Homebrew distribution

`bwx-cli` is published through the shared personal tap at
**[`DrewCarlson/homebrew-tap`](https://github.com/DrewCarlson/homebrew-tap)**.
That tap holds every Homebrew-distributed project from this account
(`ktpack`, `bwx-cli`, …), one formula file per project under
`Formula/`.

End users install with:

```sh
# One-shot:
brew install DrewCarlson/tap/bwx-cli

# Or, after `brew tap DrewCarlson/tap` once:
brew install bwx-cli
```

The formula at `packaging/homebrew/bwx-cli.rb` is the source of truth.
On every stable release, `.github/workflows/homebrew-bump.yaml`
renders the template (filling in `version` + SHA256s for each arch),
opens a PR against `DrewCarlson/homebrew-tap` updating
`Formula/bwx-cli.rb`, and **enables auto-merge** so the PR squashes
itself the moment any tap-side checks pass.

---

## One-time setup (you, ~5 min)

The tap repo already exists, so this is just secret + repo-setting
flips on the source side.

### a) Mint a fine-grained PAT for the bump workflow

GitHub → Settings → Developer settings → Personal access tokens →
Fine-grained tokens → Generate new token.

- **Token name**: `bwx-cli-homebrew-bump`
- **Resource owner**: `DrewCarlson`
- **Repository access**: Only select repositories →
  `DrewCarlson/homebrew-tap`
- **Repository permissions** →
  - **Contents**: Read and write
  - **Pull requests**: Read and write
  - everything else: No access
- **Expiration**: longest your policy allows — the bump workflow
  fails noisily when it expires, so you'll know to rotate.

Add it as a repo secret on `drewcarlson/bwx-cli`:

- Settings → Secrets and variables → Actions → New repository secret
- Name: `HOMEBREW_TAP_TOKEN`
- Value: the PAT you just generated.

### b) Enable "Allow auto-merge" on the tap

Otherwise the bump workflow opens the PR but `gh pr merge --auto`
prints a warning and the PR sits there waiting for you. To enable:

- Go to <https://github.com/DrewCarlson/homebrew-tap/settings>
- Under **Pull Requests**, tick **"Allow auto-merge"**.

If the tap has no required CI checks, GitHub merges the PR
immediately. If you add `brew test-bot` or similar later, auto-merge
waits for those.

---

## What the bump workflow does on each release

1. Triggers on `release` workflow completion for any `v*` tag.
2. Skips prerelease tags (`v2.0.0-rc01`, `v2.1.0-beta1`, …) so the
   tap only ever points at stable versions.
3. Downloads `SHA256SUMS` from the GitHub Release the workflow just
   created and published. Looks up checksums for the four binary
   tarballs:
   - `bwx-cli-VERSION-aarch64-apple-darwin.tar.gz`
   - `bwx-cli-VERSION-x86_64-apple-darwin.tar.gz`
   - `bwx-cli-VERSION-aarch64-unknown-linux-musl.tar.gz`
   - `bwx-cli-VERSION-x86_64-unknown-linux-musl.tar.gz`
4. Rewrites `__VERSION__` and `__SHA256_*__` placeholders in
   `bwx-cli.rb`.
5. Clones `DrewCarlson/homebrew-tap`, branches off `main` as
   `bump/bwx-cli-VERSION`, drops the rendered formula at
   `Formula/bwx-cli.rb`, force-pushes the branch, and opens (or
   updates) a PR titled `bwx-cli VERSION`.
6. Calls `gh pr merge --auto --squash` so the PR self-merges as soon
   as required checks pass (or immediately, if there are none).

After merge, `brew update && brew upgrade bwx-cli` picks up the new
version with no further intervention.

---

## Verifying a PR locally before merging

If you want to sanity-check a release manually before letting
auto-merge land it (e.g., after a major version bump):

```sh
gh pr checkout <PR-number> --repo DrewCarlson/homebrew-tap
brew install --build-from-source ./Formula/bwx-cli.rb
brew test bwx-cli
brew audit --strict --online bwx-cli
brew uninstall bwx-cli   # leave no trace once you're done verifying
```

`--build-from-source` here is a misnomer — for our binary-install
formula it just downloads + verifies the tarball + sha256, then runs
the `install` and `test` blocks. Catches any issue before it lands
on real users.
