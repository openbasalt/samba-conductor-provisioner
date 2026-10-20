# conductor-provisioner

Delegated Active Directory writes for Samba Conductor: a small service that
holds a least-privilege account on the managed OUs and executes typed
operations for conductor over a local socket, with its own rules that hold
even if conductor is compromised.

Part of Samba Conductor v2. Design: [docs/design.md](docs/design.md) and the
family's [architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md).

## What it does

- Issues one-time invitation and password reset tokens for conductor,
  stores only their hash, checks them without consuming them, and bounds
  them to the account's SID, objectGUID and `pwdLastSet`.
- With a valid token: sets the account's password, clears a lockout on a
  reset, enables an invited account (only one that was disabled when the
  invitation was issued).
- Answers what conductor needs to show on a user page: in the delegated
  scope or not, privileged or not and why, pending tokens.
- Applies the Google-first plan for conductor: creates an account
  (disabled, random password, Google-first marker), changes its
  Google-owned attributes, enables or disables it and moves it within its
  scope OU, only for accounts carrying the marker the request names.

## Safety rules

| Rule | How |
|---|---|
| Least privilege | one account, member of Domain Users only, with Reset Password and three attributes on user objects below the managed OUs, plus, for Google-first, create, move and the Google-owned attributes of user objects there ([docs/delegation.md](docs/delegation.md)); no security descriptor writes, no group membership writes |
| Scope | every target is read fresh by SID and must be strictly below a configured OU (parsed DN comparison, no referrals); built-in containers cannot be configured |
| Privileged accounts are untouchable | the `ad` module's privilege index (administrative groups, nested; `adminCount`; rights or ownership on the domain head, OUs, AdminSDHolder, GPOs) plus the account's own groups read at operation time |
| Ceilings | hourly ceilings per operation kind and a daily limit per account, from the service's own root-owned configuration |
| Only conductor | Unix socket, SO_PEERCRED: conductor's user only; typed, allowlisted, strictly decoded requests |
| No password at rest | a new password is sent to AD and forgotten: never logged, audited, stored or returned; the service's own password is kept sealed in memory |
| Audit | every change and every refusal in a hash chain keyed with the state key (`audit verify`) |

## Commands

```
conductor-provisioner serve
conductor-provisioner status
conductor-provisioner audit verify|export
conductor-provisioner delegation preview --ou DN [--account-sid SID] [--google-first]
conductor-provisioner healthcheck
conductor-provisioner version
```

Install (packages for Debian, Ubuntu, Fedora and Basalt OS, or from
source): [docs/install.md](docs/install.md). Configuration:
[docs/config.md](docs/config.md). Usage: [docs/usage.md](docs/usage.md).

## Development

```sh
make check      # gofmt, go vet, staticcheck, govulncheck, go test -race
make fuzz       # short fuzz run of the protocol decoder
make lab-test   # against the Samba lab (environment in internal/labtest)
make package    # .deb, .rpm and the SELinux policy package in dist/
make lintian rpmlint
```

The `provapi` package is the protocol conductor imports (standard library
only). See [CONTRIBUTING.md](CONTRIBUTING.md).

License: Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).
