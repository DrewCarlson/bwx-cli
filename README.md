# rbw

Unofficial [Bitwarden](https://bitwarden.com/) CLI with a persistent
background agent — commands don't re-prompt for the master password on
every use, similar to `ssh-agent`.

This fork adds first-class macOS support: Touch ID unlock, native
password dialogs, SSH commit signing, and a one-shot setup command.
On Linux/BSD it's a drop-in replacement for upstream rbw.

## Features

- **Persistent agent.** Vault keys live in memory until `lock_timeout`
  of inactivity.
- **Touch ID unlock (macOS).** Enroll once, and biometry replaces the
  master password. The password is only re-entered at enrollment time
  or when biometry is invalidated.
- **Per-operation biometric gate.** Optionally require Touch ID before
  each vault read or SSH sign, with one prompt per `rbw <command>`.
- **Native macOS prompts.** Master password + 2FA code entry render as
  system Aqua dialogs; pinentry isn't required.
- **SSH agent built in.** Serve vault-stored SSH keys, including git
  commit/tag signing via `gpg.format = ssh`.
- **GUI-app integration.** `rbw setup-macos` wires `SSH_AUTH_SOCK` into
  launchd so IntelliJ, GitHub Desktop, Finder-launched tools, etc. see
  the agent without per-app config.

## Install

### macOS

```sh
git clone <fork-url> rbw && cd rbw
./scripts/install.sh          # build, install, code-sign
rbw setup-macos               # LaunchAgents + SSH_AUTH_SOCK for GUI apps
```

### Everywhere else

| Platform        | Command                                   |
|-----------------|-------------------------------------------|
| Arch            | `pacman -S rbw` (or `rbw-git` from AUR)   |
| Debian / Ubuntu | `apt install rbw`                         |
| Fedora / EPEL   | `dnf install rbw`                         |
| Homebrew        | `brew install rbw`                        |
| Nix             | `nix-shell -p rbw`                        |
| Alpine          | `apk add rbw`                             |
| From source     | `cargo install --locked rbw` + `pinentry` |

## Usage

```sh
rbw config set email you@example.com
rbw config set base_url https://vault.example.com   # self-hosted only

rbw register        # only for the official bitwarden.com server
rbw login           # master password + 2FA
rbw sync

rbw add <name>
rbw ls
rbw get <name>      # --full for notes, --field for a specific field,
                    # --raw for JSON
rbw code <name>     # TOTP
rbw edit <name>     # opens $EDITOR
rbw remove <name>
rbw lock            # drop keys from memory

rbw help            # full reference
```

Commands auto-unlock and auto-login as needed. `rbw get` accepts a
name, UUID, or URL.

**Bitwarden.com users:** run `rbw register` once with your
[personal API key](https://bitwarden.com/help/article/personal-api-key/)
before `rbw login`. The official server's bot detection rejects CLI
clients that haven't registered.

## Touch ID unlock (macOS)

Enroll once:

```sh
rbw unlock                  # master password
rbw touchid enroll          # wrap vault keys under a biometric key
rbw touchid status          # confirm
```

After enrollment Touch ID alone unlocks the vault. The master password
is needed again only if you `rbw touchid disable`, change your
enrolled fingerprint set, or re-authenticate with the server.

Optionally prompt Touch ID on each sensitive operation:

```sh
rbw config set touchid_gate all       # every vault read + sign
rbw config set touchid_gate signing   # only SSH signs + TOTP codes
rbw config set touchid_gate off       # default
```

Prompts are coalesced: one `rbw <command>` triggers one Touch ID
dialog regardless of how many internal decrypts it performs.

## SSH agent & git commit signing

rbw-agent exposes an SSH agent that serves SSH keys stored in your
vault. Store an "SSH Key" item, then:

```sh
# Configured automatically by `rbw setup-macos`; explicit equivalent:
export SSH_AUTH_SOCK="$(rbw ssh-socket)"

ssh-add -L                  # list keys
ssh user@host               # authenticate with a vault-stored key
```

Git commit signing via `gpg.format = ssh`:

```sh
git config --global gpg.format ssh
git config --global user.signingkey "$(rbw ssh-public-key <entry>)"
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Optional, for `git log --show-signature`:
rbw ssh-allowed-signers > ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

Add a confirmation prompt before each signature (defence in depth
against a process silently signing while the agent is unlocked):

```sh
rbw config set ssh_confirm_sign true
```

**GUI git clients** (IntelliJ, GitHub Desktop) only see
`SSH_AUTH_SOCK` from launchd's environment, which is what
`rbw setup-macos` populates. After running it, Cmd-Q any already-open
editor and relaunch — they only pick up the new env on launch.

**IntelliJ IDEs specifically:** Settings → Version Control → Git →
"Native" (not Built-in). JGit doesn't honor `gpg.format = ssh`.

## Configuration

```sh
rbw config set <key> <value>
rbw config show                  # all keys (JSON)
rbw config show <key>            # single value
rbw config unset <key>
```

| Key | Default | |
|---|---|---|
| `email` | — | Required. |
| `base_url` | `https://api.bitwarden.com` | Self-hosted server URL. |
| `lock_timeout` | `3600` | Seconds idle → re-lock. |
| `sync_interval` | `3600` | Seconds between auto-syncs. `0` disables. |
| `touchid_gate` | `off` | `off` / `signing` / `all`. |
| `macos_unlock_dialog` | `true` (macOS) | Native dialog vs. pinentry. |
| `ssh_confirm_sign` | `false` | Pinentry CONFIRM before each SSH sign. |
| `pinentry` | `pinentry` | Pinentry binary to use. |

### Profiles

Set `RBW_PROFILE=<name>` to keep an independent vault, config, and
agent under that name.

## 2FA

Supported: Email, Authenticator App, Yubico OTP security key.

Not supported: WebAuthn / Passkey, Duo. Add a supported mechanism
alongside them — rbw will use the supported one while your web/mobile
clients keep whichever you prefer.

---

# Appendix: macOS internals

## Code signing

`cargo install` produces unsigned binaries; macOS AMFI kills unsigned
processes that touch the Keychain. `scripts/install.sh` wraps
`cargo install` and runs `scripts/sign-macos.sh`, which auto-picks the
strongest signing identity on your machine:

1. `$IDENTITY` env var (explicit override).
2. Developer ID Application cert (paid Apple Developer program).
3. Apple Development cert (free via Xcode).
4. Ad-hoc.

Keychain security varies by tier:

| Identity                 | Keychain item ACL                                |
|--------------------------|--------------------------------------------------|
| Developer ID Application | OS-enforced biometric ACL — strongest.           |
| Apple Development        | Plain item; Touch ID enforced by rbw-agent only. |
| Ad-hoc                   | Same as Apple Development.                       |

Only Developer ID Application carries `keychain-access-groups` on a
CLI binary; the other tiers would need a provisioning profile, which
bare binaries can't have. The runtime detects which entitlements the
installed binary actually holds and branches automatically — the same
source builds all three tiers. Upgrading tiers later: re-run
`./scripts/install.sh`, then `rbw touchid disable && rbw touchid enroll`
to migrate the Keychain item.

## `rbw setup-macos`

Installs two LaunchAgents under `~/Library/LaunchAgents/`:

- **`net.tozt.rbw.ssh-auth-sock`** — runs `~/bin/rbw-set-ssh-sock` at
  login, which calls `launchctl setenv SSH_AUTH_SOCK $(rbw ssh-socket)`.
  Puts the socket into launchd's environment so GUI apps inherit it.
- **`net.tozt.rbw.agent`** — runs `rbw-agent --no-daemonize` under
  launchd supervision with `KeepAlive`. Log output lands in
  `~/Library/Application Support/rbw/launchd-agent.{out,err}`.

`rbw teardown-macos` unloads both and removes the files.
