# Usage

## Commands

Every command takes `--config FILE` (default
`/etc/conductor-provisioner/provisioner.toml`).

| Command | What it does |
|---|---|
| `conductor-provisioner serve` | runs the API for conductor (started by the systemd units) |
| `conductor-provisioner status` | configuration summary (account, scope OUs, ceilings, token lifetimes), tokens by state, audit rows and, with the state key, whether the chain is intact |
| `conductor-provisioner audit verify` | checks the audit hash chain with the state key |
| `conductor-provisioner audit export` | writes the audit log as JSON lines, oldest first |
| `conductor-provisioner delegation preview --ou DN [--account-sid SID]` | prints the `samba-tool dsacl set` commands that delegate the OU to the configured account, and the command to verify them ([delegation.md](delegation.md)) |
| `conductor-provisioner healthcheck` | exits 0 when the configuration loads and the API socket exists |
| `conductor-provisioner version` | prints the version |

Exit codes: 0 success, 1 error, 2 usage, 3 the audit chain is broken.

`status` and `audit` read the state database and the credentials, so run
them as root (or as the service user with access to the credential
directory).

## What conductor shows

conductor talks to the service only through its socket. With the
provisioner enabled in conductor:

- the user page asks `user.check` and shows whether the account is in the
  delegated scope and not privileged; otherwise the invitation and reset
  actions are replaced by the reason (out of scope, privileged with its
  kinds, disabled);
- sending an invitation or a reset issues a token (`token.issue`), mails
  the link and lists the account's pending tokens (`token.list`) with a
  revoke action (`token.revoke`);
- the public link pages validate the token (`token.check`, which never
  consumes it), set the password (`password.set`) and, for an invitation,
  enable the account (`invite.complete`);
- the public reset form resolves the account by name or address
  (`user.find`) in the background and always answers the same way.

## Reading refusals

| Code | Meaning | What to do |
|---|---|---|
| `out_of_scope` | the account is not below a scope OU, or no scope is configured | move the account, or add (and delegate) its OU |
| `privileged` | the account holds privileged rights | act on it directly in AD with an administrator account |
| `rate_limited` | an hourly ceiling or the daily limit per account | wait, or raise the ceiling in `provisioner.toml` |
| `stale` | the account's password, identity or state changed since the token was issued | issue a new token |
| `expired`, `used`, `revoked` | the token's state | issue a new token |
| `password_policy` | the domain refused the password (`reason` says why) | choose another password |
| `directory` | the directory could not be read or refused a write | check `journalctl -u conductor-provisioner` and the delegation |

Every refusal is in the audit log with its code and details
(`audit export`).
