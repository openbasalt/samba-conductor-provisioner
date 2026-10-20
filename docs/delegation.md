# The delegated account

conductor-provisioner signs in to the domain with one account that has
rights on the managed OUs only. This page creates that account, grants the
rights, verifies them and rotates its password. Run the commands on a
domain controller as a domain administrator (add `-H` and credentials as
usual when you run them elsewhere).

## Create the account

The account is a member of Domain Users only, is marked sensitive (it can
never be delegated), and its password exists only in the credential file
the service reads.

```sh
# Generate the password into the credential file (root only).
install -d -m 0700 /etc/conductor-provisioner/credentials
umask 077
openssl rand -base64 33 | tr -d '\n' > /etc/conductor-provisioner/credentials/account-password

samba-tool user create svc-conductor-prov --random-password \
  --description='conductor-provisioner delegated account'
# Type the password from the file at the prompt (not on the command line).
samba-tool user setpassword svc-conductor-prov
samba-tool user sensitive svc-conductor-prov on
```

`samba-tool user sensitive` sets the "account is sensitive and cannot be
delegated" flag (`NOT_DELEGATED`, 0x100000 in `userAccountControl`). Keep
the account out of every group but Domain Users.

## Grant the rights

Each managed OU gets four access entries for the account, each inherited
only by the user objects below the OU (`CIIO`, with the `user` class
`bf967aba-0de6-11d0-a285-00aa003049e2` as inherited object type):

| Right | Entry type and object | Used for |
|---|---|---|
| Reset Password (control access) | `CR;00299570-246d-11d0-a768-00aa006e0529` | `password.set` |
| Write `lockoutTime` | `WP;28630ebf-41d5-11d1-a9c1-0000f80367c1` | clearing a lockout on reset |
| Write `pwdLastSet` | `WP;bf967a0a-0de6-11d0-a285-00aa003049e2` | the password reset writes it |
| Write `userAccountControl` | `WP;bf967a68-0de6-11d0-a285-00aa003049e2` | enabling an invited account |

Nothing else is needed. `conductor-provisioner delegation preview` prints
the exact commands for an OU and the configured account, with the
account's SID resolved:

```sh
sudo -u conductor-provisioner conductor-provisioner delegation preview \
  --ou 'OU=People,OU=Lab,DC=example,DC=com'
# or, without the account's credential:
conductor-provisioner delegation preview --ou 'OU=People,OU=Lab,DC=example,DC=com' \
  --account-sid S-1-5-21-1111111111-2222222222-3333333333-1234
```

The output has this form (one line per entry):

```sh
samba-tool dsacl set --objectdn='OU=People,OU=Lab,DC=example,DC=com' \
  --sddl='(OA;CIIO;CR;00299570-246d-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;<account SID>)'
samba-tool dsacl set --objectdn='OU=People,OU=Lab,DC=example,DC=com' \
  --sddl='(OA;CIIO;WP;28630ebf-41d5-11d1-a9c1-0000f80367c1;bf967aba-0de6-11d0-a285-00aa003049e2;<account SID>)'
samba-tool dsacl set --objectdn='OU=People,OU=Lab,DC=example,DC=com' \
  --sddl='(OA;CIIO;WP;bf967a0a-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;<account SID>)'
samba-tool dsacl set --objectdn='OU=People,OU=Lab,DC=example,DC=com' \
  --sddl='(OA;CIIO;WP;bf967a68-0de6-11d0-a285-00aa003049e2;bf967aba-0de6-11d0-a285-00aa003049e2;<account SID>)'
```

Then add the OU to `[scope] ous` in `provisioner.toml` and restart the
service. An OU in the scope without the delegation makes the writes fail
with `directory` (access denied); a delegation without the scope entry is
never used.

## What the account must not have

- membership of Domain Admins, Enterprise Admins, Administrators, Account
  Operators or any other group but Domain Users;
- rights on the domain head, on `CN=Users`, on `CN=System` or on the
  `Domain Controllers` OU;
- delete or delete-tree rights, create-child rights, `WRITE_DAC` or
  `WRITE_OWNER` anywhere, or write access to `adminCount`, `member` or
  `nTSecurityDescriptor`;
- an interactive use: the password is only in the credential file.

The service checks every target itself (scope, privileged accounts), so a
wider delegation does not widen what it does; it only widens what a stolen
password can do.

## Verify

```sh
samba-tool dsacl get --objectdn='OU=People,OU=Lab,DC=example,DC=com' | grep '<account SID>'
samba-tool group listmembers 'Domain Admins' | grep -i svc-conductor-prov   # no output
samba-tool user show svc-conductor-prov --attributes=memberOf,userAccountControl
```

The first command lists exactly the four entries above (in the descriptor
of the OU they appear as `OA;CIIO;...` entries). `memberOf` is empty
(Domain Users is the primary group) and `userAccountControl` includes
0x100000.

## Rotate the password

```sh
umask 077
openssl rand -base64 33 | tr -d '\n' > /etc/conductor-provisioner/credentials/account-password.new
samba-tool user setpassword svc-conductor-prov    # type the new password at the prompt
mv /etc/conductor-provisioner/credentials/account-password.new \
   /etc/conductor-provisioner/credentials/account-password
systemctl restart conductor-provisioner.service
```

The service reads the credential once at start, so restart it right after
the change. Requests in the few seconds in between fail with `directory`
and can be retried.
