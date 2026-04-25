# AUR packaging

Two PKGBUILDs live here. They are *not* used by this repo's CI — they
are the source of truth for what gets pushed to the
`aur.archlinux.org` git repos under the same names.

## One-time AUR account setup

```sh
ssh-keygen -t ed25519 -f ~/.ssh/aur -C "aur@drews.website"
cat ~/.ssh/aur.pub
# → paste under https://aur.archlinux.org/account → SSH Public Key
cat >> ~/.ssh/config <<'EOF'
Host aur.archlinux.org
  IdentityFile ~/.ssh/aur
  User aur
EOF
```

## Pushing a new release

```sh
# Per-package, in a separate clone of the AUR repo:
git clone ssh://aur@aur.archlinux.org/bwx-cli.git aur-bwx-cli
cd aur-bwx-cli

# Copy the PKGBUILD from this repo, regenerate .SRCINFO.
cp /path/to/bwx-cli/packaging/aur/bwx-cli/PKGBUILD .
makepkg --printsrcinfo > .SRCINFO

# Sanity-check it builds in a clean chroot first.
makepkg -sci

git add PKGBUILD .SRCINFO
git commit -m "v$(grep '^pkgver=' PKGBUILD | cut -d= -f2)"
git push
```

For `bwx-cli-git` the same flow applies; the `pkgver()` function picks
up commits as users update.

## Bumping `bwx-cli` for a new release

1. Push a `vX.Y.Z` tag here.
2. `curl -L https://github.com/drewcarlson/bwx-cli/archive/refs/tags/vX.Y.Z.tar.gz | sha256sum`
3. Edit `packaging/aur/bwx-cli/PKGBUILD` — bump `pkgver` and replace `SKIP` with the new sha256.
4. Follow the push flow above.
