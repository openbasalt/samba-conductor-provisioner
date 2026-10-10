# conductor-provisioner: design

## Role

conductor-provisioner holds the only standing write credential on Active
Directory in the Samba Conductor family: a least-privilege account
delegated on the managed OUs only (see [delegation.md](delegation.md)). It
runs as its own systemd unit and user, separate from conductor's web
process, so the web process keeps no standing write credential.

It executes a small set of typed operations for conductor over a Unix
socket and enforces its own rules even when conductor is compromised:

- one-time invitation and password reset tokens: it issues them, stores
  only their hash, checks them and consumes them;
- with a valid token: set the account's password, clear a lockout on a
  reset, enable an invited account;
- the Google-first plan operations: create an account, change its
  Google-owned attributes, enable or disable it, move it within its scope
  OU (see [Google-first plan operations](#google-first-plan-operations)).

It never takes free-form LDAP, never writes outside the configured OUs,
never touches a privileged account, never deletes, never changes a group
membership and never writes a security descriptor.

## Components

| Part | What it does |
|---|---|
| `provapi` | The protocol: types, validation, framing and a client. Standard library only, imported by conductor. |
| `internal/server` | The service: typed operation registry, invariants, ceilings, tokens, audit; the socket listener. |
| `internal/directory` | The directory reads and writes the service needs, as an interface, and its implementation with the `ad` module (Kerberos or simple bind over LDAPS, domain CA pinned). |
| `internal/store` | SQLite (WAL): tokens and the hash-chained audit log. |
| `internal/config` | `provisioner.toml`, strict (unknown keys refused). |

## Invariants

Checked by the service on every operation that names an account,
whatever conductor sends:

1. Scope. The account is read fresh from the directory by its SID; its DN
   as the directory returns it is parsed (RFC 4514) and must be strictly
   below one of the `[scope] ous`, compared component by component and
   case-insensitively. Escaped commas, extra spaces, a different case or a
   trailing component neither widen nor narrow the scope. No referral is
   chased. With no scope OU every such operation is refused. Scope OUs
   that are the domain head, `CN=Users`, `CN=Builtin`, `CN=System`,
   `CN=Computers`, the `Domain Controllers` OU or below them are refused
   when the configuration loads.
2. Not privileged. The `privilege` index of the `ad` module (members,
   direct or nested, of the administrative groups and of conductor's role
   groups; `adminCount = 1`; owners and holders of more than read on the
   domain head, an OU, AdminSDHolder or a Group Policy object), rebuilt
   when older than `index_cache_seconds`, plus the account's own
   `adminCount` and `tokenGroups` read at operation time. Samba does not
   run SDProp, so this check, not AdminSDHolder, protects those accounts.
   The delegated account itself holds rights on the scope OUs, so it is
   privileged and can never act on itself. A refusal returns the reason
   kinds only; the details go to the audit log.
3. A user account: not a computer, not a group.
4. Ceilings: sliding one-hour windows per kind (token issues, password
   sets, enables, creates, updates, moves, disables) from the service's
   own configuration, which conductor cannot change; 0 refuses everything. A refusal is logged at warning
   level at most once a minute. The windows are in memory and start empty
   after a restart. Tokens per account are limited per 24 hours as well.
5. Token binding. A token is bound to the account's SID, objectGUID and
   `pwdLastSet` at issue. If the password changed in between (by the user,
   an administrator or another token) the token is stale and revoked.
6. Password material never persists: a new password crosses the socket
   once, goes to the directory, and is never logged, audited, stored or
   returned. The raw token is returned once by `token.issue` and stored
   only as a hash.
7. Marker. `user.update`, `user.set_enabled` and `user.move` act only on
   an account whose `msDS-cloudExtensionAttribute1` equals the marker the
   request names (`google-first:` and the Google user ID); no operation
   writes the marker after `user.create`.

## Tokens

| Field | Meaning |
|---|---|
| hash | SHA-256 of `conductor-provisioner-token`, a NUL byte and the raw token (32 random bytes, base64url) |
| purpose | `invite` or `reset` |
| sid, objectGUID, pwdLastSet | the binding of invariant 5 |
| issued_by, reference | the actor conductor acted for, and conductor's own correlation value |
| expires_at | `invite_hours` or `reset_minutes` after issue |
| state | `open`, `password_set` (invitation after its password step), `used`, `revoked`, `expired` |

Issuing a token revokes the account's open tokens of the same purpose.
`token.check` never consumes. A reset token is consumed by `password.set`.
An invitation is consumed by `invite.complete`, which must come within
`complete_minutes` of the password step (and before the invitation
expires). `invite.complete` enables the account only if it was disabled
when the invitation was issued: an account an administrator disabled
after that is never re-enabled (the token is revoked as stale). A reset is
refused for a disabled account. Closed tokens are kept 90 days for
`token.list` and the daily limit, then deleted.

## Protocol

One request and one response per connection on the Unix socket, each a
JSON object on one line of at most 256 KiB. Requests carry the protocol
version, a request ID, the operation, the actor (`user`, `sid`, `session`,
`ip`; `user = "-public-"` without a SID for the public link and reset
pages) and the parameters, decoded strictly. The peer is checked with
SO_PEERCRED on every connection: only conductor's user is served.

| Operation | Parameters | Result | Effect |
|---|---|---|---|
| `status` | none | version, account, scope OUs, index build time, ceilings with their use, tokens by state | none |
| `user.check` | `sid` | `sid`, `sam`, `dn`, `mail`, `enabled`, `locked`, `in_scope`, `privileged`, `privileged_reasons` (kinds), `pending_tokens` | none |
| `user.find` | `username_or_mail` | as `user.check`; exactly one user account must match by `sAMAccountName` or `mail` | none |
| `token.issue` | `sid`, `purpose`, `reference` | `token` (once), `token_id`, `expires_at`, `sam`, `dn`, `mail` | new token, older open tokens of the purpose revoked |
| `token.check` | `token` | `token_id`, `purpose`, `sam`, `dn`, `mail`, `sid`, `expires_at`, `password_set` | none (a stale or expired token is marked so) |
| `password.set` | `token`, `new_password`, `unlock` | `sam`, `dn`, `mail`, `purpose` | password reset (no change at next sign-in), lockout cleared on a reset when `unlock`, token consumed (reset) or moved to `password_set` (invitation) |
| `invite.complete` | `token` | `sam`, `dn` | account enabled, token consumed |
| `token.revoke` | `sid`, `purpose` (optional), `reason` | `revoked` | open tokens revoked |
| `token.list` | `sid` | list of `token_id`, `purpose`, `issued_at`, `issued_by`, `expires_at`, `state`, `reference` | none |
| `user.create` | `scope_ou`, `sam`, `upn`, `cn`, `mail`, `given_name`, `sn`, `display_name`, `fields`, `marker`, `reference` | `sid`, `object_guid`, `sam`, `dn` | account created disabled with a random password, `pwdLastSet` 0 and the marker |
| `user.update` | `sid`, `changes` (`attr`, `before`, `after`), `marker`, `reference` | `sid`, `sam`, `dn`, `enabled`, `changed` | Google-owned attributes replaced |
| `user.set_enabled` | `sid`, `enabled`, `marker`, `reference` | as `user.update` | account enabled or disabled; a disable revokes the account's open tokens |
| `user.move` | `sid`, `to_ou`, `marker`, `reference` | as `user.update` | account moved to another OU below the same scope OU |

Error codes: `invalid_params`, `not_found`, `out_of_scope`, `privileged`
(with `kinds`), `rate_limited`, `expired`, `used`, `revoked`, `stale`,
`password_policy` (with `reason`: `too_short`, `complexity`, `history`,
`too_young`, `other`), `exists` (with `kinds`), `conflict` (with `kinds`),
`marker_mismatch`, `schema_missing`, `directory`, `internal`. The client reports a
service it cannot reach as `unavailable`.

Operations live in a typed registry: each one has its parameter type in
`provapi`, a handler in `internal/server`, and goes through the same
target read, invariants, ceilings and audit. Adding an operation is
additive for the protocol version; changing an existing one bumps it.

## Google-first plan operations

conductor-sync computes a plan from Google Workspace and conductor applies
it through these operations. The service trusts neither: every operation
reads the account fresh, applies the invariants above and refuses rather
than guesses.

`user.create` creates the account in `scope_ou`, which must be a scope OU
or an OU below one and must exist. The account is created in one request,
disabled, with `pwdLastSet` 0, the marker in `msDS-cloudExtensionAttribute1`
and a password of 32 random characters (four character classes, none of
the account's names) generated by the service and never logged, stored or
returned; the user sets the real password through an invitation. Optional
attributes are `givenName`, `sn`, `displayName` and, in `fields`, `title`,
`department`, `employeeID`, `telephoneNumber` and `mobile`. It is refused
with `schema_missing` when the schema lacks `msDS-cloudExtensionAttribute1`,
and with `exists` (and `kinds`) when the DN exists or when the
`sAMAccountName`, the `userPrincipalName`, the address (as `mail`,
`userPrincipalName` or an SMTP entry of `proxyAddresses`) or the marker is
used by any object anywhere in the domain. It writes no group membership
and no attribute outside this list, so nothing it creates is privileged.

`user.update` replaces `givenName`, `sn`, `displayName`, `mail`,
`proxyAddresses`, `title`, `department`, `employeeID`, `telephoneNumber`
or `mobile`, and nothing else. Every change carries the value the plan
read (`before`); when the current value differs the whole update is
refused with `conflict` and nothing is written. `proxyAddresses` travels
as its values sorted and joined with a line feed and is compared as a set.
A new `mail` already used by another object is refused with `exists`.

`user.set_enabled` enables or disables the account. A disable also revokes
the account's open tokens, so a pending invitation cannot enable it again.

`user.move` moves the account to `to_ou`, an existing OU; the account's
current parent and `to_ou` must both be below the same scope OU (the
quarantine OU of a Google-first scope is inside its managed OU).

`user.set_enabled` and `user.move` with nothing to write (already in that
state, already in that OU) succeed with `changed = false` and count
toward no ceiling. With the `ad` module version this release pins, the
directory implementation cannot write `msDS-cloudExtensionAttribute1`,
`employeeID` or `proxyAddresses`: `user.create` and updates of those two
attributes are refused with `directory` before any write.

## Audit

Every mutating operation (`token.issue`, `password.set`,
`invite.complete`, `token.revoke`, `user.create`, `user.update`,
`user.set_enabled`, `user.move`) is audited, successful or not; any
other operation is audited when it is refused, with its error code, and
so is an unreadable request. A row holds: sequence, time, actor,
operation, target SID and sAMAccountName, token ID, reference, result,
detail, the previous row's hash and its own. The hash is HMAC-SHA-256,
keyed with a key derived from the `state-key` credential, over the previous
hash and the row: a row cannot be changed, removed or added with a valid
chain without that key, even by someone who can write the database file.
`conductor-provisioner audit verify` checks the chain with the key. For
`user.find` the detail holds a 16-hex-digit digest of the lower-cased
identifier, never the name or address. For the plan operations the detail
holds the marker (`user.create`), the parent OU, the names of the changed
attributes, the source and target OUs of a move and what collided, never
attribute values, names or addresses; the reference is the plan run.

## Threat notes

| If this is compromised | It can | It cannot |
|---|---|---|
| conductor's web process | issue and use tokens, so set passwords and enable invited accounts, for ordinary accounts below the scope OUs, within the ceilings and the daily limit per account; revoke tokens; create disabled Google-first accounts, change their Google-owned attributes, enable, disable and move them within their scope OU, within the ceilings | act on privileged accounts or outside the scope OUs; act on an account without its marker; change a marker; raise the ceilings; write any other attribute or a group membership; delete; read a stored token |
| the provisioner host user | what the delegated account can do (see [delegation.md](delegation.md)): reset passwords and write the three attributes on user objects below the delegated OUs; with the Google-first delegation also create, move, delete and write the Google-owned attributes of user objects there | anything else in the directory |
| the state database (read) | see token metadata and the audit log | recover a token or a password |
| the state database (write) | delete or corrupt tokens and audit rows | forge a valid audit chain without the state key |
| a link in transit | use it before it expires, once | use it after the password changed, after it was used or revoked |

The service never accepts a connection from another local user than
conductor's, has no network listener, and runs under a sandboxed systemd
unit (`deploy/systemd/`).
