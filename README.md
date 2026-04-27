# bwx

Bitwarden in your terminal, without the master-password prompt every
time. `bwx` keeps your vault unlocked in a background agent — like
`ssh-agent` for your passwords.

Fork of [`rbw`](https://github.com/doy/rbw) that adds first-class
macOS support (Touch ID unlock, native dialogs, signed + notarized
binaries, built-in SSH agent for git commit signing, one-shot setup).
Drop-in replacement on Linux/BSD.

## Features

- **Persistent agent.** Vault keys live in memory until `lock_timeout`
  of inactivity.
- **Touch ID unlock (macOS).** Enroll once, and biometry replaces the
  master password. The password is only re-entered at enrollment time
  or when biometry is invalidated.
- **Per-operation biometric gate.** Optionally require Touch ID before
  each vault read or SSH sign, with one prompt per `bwx <command>`.
- **Native macOS prompts.** Master password + 2FA code entry render as
  system Aqua dialogs; pinentry isn't required.
- **SSH agent built in.** Serve vault-stored SSH keys, including git
  commit/tag signing via `gpg.format = ssh`.
- **One-shot macOS setup.** `bwx setup-os` installs the LaunchAgent
  that keeps `bwx-agent` alive and registers the SSH-agent socket so
  terminal sessions (and the GUI apps they launch) can use it via a
  one-line shell-rc export.

## Install

### macOS

```sh
brew install DrewCarlson/tap/bwx-cli
bwx setup-os                  # LaunchAgent that keeps bwx-agent alive
```

### Everywhere else

| Channel                  | Command                                                                            |
|--------------------------|------------------------------------------------------------------------------------|
| crates.io (any platform) | `cargo install --locked bwx-cli` (binaries are `bwx` / `bwx-agent`)                |
| Arch (AUR — release)     | `yay -S bwx-cli` (or any AUR helper)                                               |
| Arch (AUR — git)         | `yay -S bwx-cli-git`                                                               |
| Nix flake                | `nix profile install github:drewcarlson/bwx-cli`                                   |
| Debian / Ubuntu (`.deb`) | download from [GitHub Releases][rel] → `sudo dpkg -i bwx-cli_*_amd64.deb`          |
| Fedora / RHEL (`.rpm`)   | download from [GitHub Releases][rel] → `sudo dnf install ./bwx-cli-*.x86_64.rpm`   |
| Standalone tarball       | download from [GitHub Releases][rel], extract, put `bwx`/`bwx-agent` on PATH       |
| From source (any)        | `git clone … && ./scripts/install.sh` (auto-runs `scripts/sign-macos.sh` on macOS) |

[rel]: https://github.com/drewcarlson/bwx-cli/releases

Each tagged release builds Linux `x86_64` + `aarch64` (glibc and musl)
and macOS `arm64` + `x86_64` artifacts, attached to the GitHub Release.
On Linux you'll also want `pinentry` from your distro so the
master-password prompt has a UI.

## Usage

### First-time setup

```sh
bwx config set email you@example.com
bwx config set base_url https://vault.example.com   # self-hosted only

bwx register   # bitwarden.com only
bwx login      # master password + 2FA
bwx sync
```

**Bitwarden.com users:** the official server's bot detection rejects
CLI clients that haven't called `register` once with a [personal API
key](https://bitwarden.com/help/article/personal-api-key/).
Self-hosted servers (Vaultwarden, etc.) skip this step.

### Reading entries

```sh
bwx get github.com           # password by entry name
bwx get <uuid>               # by Bitwarden item UUID
bwx get https://github.com   # by stored URI
bwx get --field totp <name>  # any single field
bwx get --full <name>        # password + fields + notes
bwx get --raw <name>         # JSON
bwx code <name>              # generated TOTP code
```

The agent auto-unlocks on the first call after `bwx login` (or after a
lock-timeout expiry).

### Adding, editing, removing

```sh
bwx add <name>               # password from $EDITOR or stdin
bwx edit <name>              # opens the entry in $EDITOR
bwx remove <name>
```

### Locking the vault

```sh
bwx lock                     # drop keys from memory immediately
bwx unlocked                 # exit 0 if unlocked, 1 if locked
```

The vault auto-locks after `lock_timeout` seconds of inactivity (1h by
default — configurable). `bwx help` lists every subcommand.

## Touch ID unlock (macOS)

Enroll once:

```sh
bwx unlock                    # master password
bwx biometric enroll          # wrap vault keys under a biometric key
bwx biometric status          # confirm
```

After enrollment Touch ID alone unlocks the vault. The master password
is needed again only if you `bwx biometric disable`, change your
enrolled fingerprint set, or re-authenticate with the server.

Optionally prompt Touch ID on each sensitive operation:

```sh
bwx config set biometric_gate all       # every vault read + sign
bwx config set biometric_gate signing   # only SSH signs + TOTP codes
bwx config set biometric_gate off       # default
```

Prompts are coalesced: one `bwx <command>` triggers one Touch ID
dialog regardless of how many internal decrypts it performs.

## SSH agent & git commit signing

bwx-agent exposes an SSH agent that serves SSH keys stored in your
vault. Store an "SSH Key" item, then:

```sh
# Configured automatically by `bwx setup-os`; explicit equivalent:
export SSH_AUTH_SOCK="$(bwx ssh-socket)"

ssh-add -L                  # list keys
ssh user@host               # authenticate with a vault-stored key
```

Git commit signing via `gpg.format = ssh`:

```sh
git config --global gpg.format ssh
git config --global user.signingkey "$(bwx ssh-public-key <entry>)"
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Optional, for `git log --show-signature`:
bwx ssh-allowed-signers > ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

Require a confirmation prompt before each signature, so a
background process can't sign silently while the agent is unlocked:

```sh
bwx config set ssh_confirm_sign true
```

**Shell + GUI app inheritance.** Modern macOS no longer propagates
`launchctl setenv` into the env of Dock- / Spotlight-launched apps.
Add this line to your shell rc so terminal sessions and the apps
they launch see the bwx ssh-agent:

```sh
export SSH_AUTH_SOCK="$(bwx ssh-socket)"   # ~/.zshrc, ~/.bashrc, …
```

GUI apps that were already open need to be Cmd-Q'd and relaunched
(so their env is re-inherited from the shell) before they pick it up.

**IntelliJ IDEs specifically:** Settings → Version Control → Git →
"Native" (not Built-in). JGit doesn't honor `gpg.format = ssh`.

## Configuration

```sh
bwx config set <key> <value>
bwx config show                  # all keys (JSON)
bwx config show <key>            # single value
bwx config unset <key>
```

| Key | Default | |
|---|---|---|
| `email` | — | Required. |
| `base_url` | `https://api.bitwarden.com` | Self-hosted server URL. |
| `lock_timeout` | `3600` | Seconds idle → re-lock. |
| `sync_interval` | `3600` | Seconds between auto-syncs. `0` disables. |
| `biometric_gate` | `off` | `off` / `signing` / `all`. |
| `macos_unlock_dialog` | `true` (macOS) | Native dialog vs. pinentry. |
| `ssh_confirm_sign` | `false` | Pinentry CONFIRM before each SSH sign. |
| `pinentry` | `pinentry` | Pinentry binary to use. |

### Profiles

Set `BWX_PROFILE=<name>` to keep an independent vault, config, and
agent under that name.

## 2FA

Supported: Email, Authenticator App, Yubico OTP security key.

Not supported: WebAuthn / Passkey, Duo. Add a supported mechanism
alongside them — bwx will use the supported one while your web/mobile
clients keep whichever you prefer.

## Verifying release artifacts

Every release artifact carries a SLSA build-provenance attestation
(signed with the release workflow's GitHub OIDC identity, recorded in
the sigstore rekor transparency log) plus a `.minisig` signature.

```sh
# GitHub-native attestation verify. Confirms the artifact was built
# by the bwx-cli release workflow on a tagged commit. Requires `gh`.
gh attestation verify bwx-cli_2.0.0_amd64.deb \
  --repo drewcarlson/bwx-cli

# Minisign — single shipped pubkey at packaging/minisign.pub.
minisign -V -p packaging/minisign.pub \
  -m bwx-cli_2.0.0_amd64.deb

# `SHA256SUMS` covers every file in the release.
sha256sum -c SHA256SUMS
```

---

# Appendix: macOS internals

## Code signing

Touch ID works on every install path. Homebrew and GitHub release
builds are signed with Developer ID and notarized; `cargo install`
and source builds are signed ad-hoc by `scripts/sign-macos.sh`,
which `scripts/install.sh` runs automatically.

The signing tier picks where the Touch ID wrapper key is stored:

- Developer ID builds carry `keychain-access-groups = ["TEAMID.bwx"]`
  and use the data-protection keychain. Items are scoped to the team,
  so other processes signed by another identity can't read them, and
  upgrades never re-prompt for keychain access.
- Ad-hoc, Apple Development, and `cargo install` builds use the
  legacy login keychain. The first run after a reinstall may show a
  one-time "always allow" prompt.

bwx detects which path applies at startup and picks the keychain
accordingly. The biometric prompt itself is identical on both:
`bwx-agent` runs `LAContext.evaluatePolicy` before releasing the
wrapper key. Items are stored with
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and don't sync to
iCloud.

`scripts/sign-macos.sh` picks the strongest available identity:
`$IDENTITY` override, then Developer ID, then Apple Development,
then ad-hoc. Set `TEAM_ID=…` if the script can't parse the team
prefix from the identity string.

## `bwx setup-os`

On macOS, installs two LaunchAgents under `~/Library/LaunchAgents/`:

- **`drews.website.bwx.ssh-auth-sock`** — runs `~/bin/bwx-set-ssh-sock` at
  login, which calls `launchctl setenv SSH_AUTH_SOCK $(bwx ssh-socket)`.
  Puts the socket into launchd's environment so GUI apps inherit it.
- **`drews.website.bwx.agent`** — runs `bwx-agent --no-daemonize` under
  launchd supervision with `KeepAlive`. Log output lands in
  `~/Library/Application Support/bwx/launchd-agent.{out,err}`.

`bwx teardown-os` unloads both and removes the files.

On non-macOS platforms the command currently prints a not-implemented
message and exits successfully.
