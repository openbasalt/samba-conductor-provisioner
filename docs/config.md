# Configuration

`/etc/conductor-provisioner/provisioner.toml`, owned by root, group
`conductor-provisioner`, mode 0640. An annotated example is
[provisioner.toml.example](../provisioner.toml.example). The file holds
no secret. Unknown keys, relative paths and values out of range are
refused when the service starts.

## [domain]

| Key | Default | Meaning |
|---|---|---|
| `realm` | required | Kerberos realm and DNS domain, for example `EXAMPLE.COM` |
| `ca_file` | required | absolute path of the domain CA (PEM) that signs the domain controllers' LDAPS certificates; only this CA is trusted |
| `preferred` | `[]` | domain controller host names tried first |
| `dcs` | `[]` | domain controller host names to use instead of DNS SRV discovery |
| `dns_servers` | `[]` | DNS servers (`address` or `address:port`) for SRV discovery instead of the system resolver |
| `simple_bind_fallback` | `false` | when no KDC answers, bind with an LDAP simple bind over LDAPS instead of Kerberos |

## [account]

| Key | Default | Meaning |
|---|---|---|
| `username` | required | sAMAccountName of the delegated account ([delegation.md](delegation.md)). Its password is the systemd credential `account-password` |

## [scope]

| Key | Default | Meaning |
|---|---|---|
| `ous` | `[]` | DNs of the OUs the account is delegated on. Every target account must be strictly below one of them. Empty: every operation that names an account is refused. Each entry must be an OU (`OU=...`) below the domain head; the domain head itself, `CN=Users`, `CN=Builtin`, `CN=System`, `CN=Computers`, `CN=ForeignSecurityPrincipals`, the `Domain Controllers` OU and anything below them are refused. Entries are normalized (case and spacing), duplicates refused |

## [privileged]

| Key | Default | Meaning |
|---|---|---|
| `extra_group_sids` | `[]` | SIDs of conductor's role groups (administrators, helpdesk, auditors); their members are privileged in addition to the built-in administrative groups and the ACL index |
| `index_cache_seconds` | `60` | 0 to 300: how long a built privilege index is reused. The target's own `adminCount` and groups are read on every operation regardless; 0 rebuilds the index for every operation |

## [tokens]

| Key | Default | Range | Meaning |
|---|---|---|---|
| `invite_hours` | `72` | 1 to 168 | validity of an invitation |
| `reset_minutes` | `30` | 5 to 120 | validity of a reset token |
| `complete_minutes` | `30` | 5 to 240 | after an invitation's password step, the time left to complete it (never beyond the invitation's own expiry) |
| `per_user_per_day` | `3` | 1 to 50 | tokens issued per account in any 24 hours, all purposes together |

## [limits]

Hourly ceilings, sliding one-hour windows kept in memory. 0 refuses
every operation of that kind.

| Key | Default | Range |
|---|---|---|
| `token_issues_per_hour` | `200` | 0 to 100000 |
| `password_sets_per_hour` | `200` | 0 to 100000 |
| `enables_per_hour` | `200` | 0 to 100000 |

## [state]

| Key | Default | Meaning |
|---|---|---|
| `database` | `/var/lib/conductor-provisioner/provisioner.db` | SQLite database (tokens, audit log), mode 0600 |

## [api]

| Key | Default | Meaning |
|---|---|---|
| `socket` | `/run/conductor-provisioner/api.sock` | socket path when the service creates the socket itself (without socket activation) |
| `socket_group` | empty | group of that socket (the service user must be a member) |
| `allowed_users` | `["conductor"]` | user names whose processes may connect (SO_PEERCRED); root is refused |
| `allowed_uids` | `[]` | the same by UID |

## Credentials

| Name | Content |
|---|---|
| `account-password` | the delegated account's password, one line |
| `state-key` | 32 bytes (raw, 64 hex digits or base64); keys the audit chain |

The unit passes them with `LoadCredential=` from
`/etc/conductor-provisioner/credentials/`. Outside the unit (the `status`,
`audit` and `delegation` commands run by root) they are read from that
directory, whose files must not be readable by group or others.
