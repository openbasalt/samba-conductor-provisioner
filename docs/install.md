# Installing conductor-provisioner

conductor-provisioner runs on the host where conductor runs (usually a
domain controller), as its own user, with systemd socket activation.

## 1. Binary and user

```sh
make build                          # bin/conductor-provisioner (CGO off, static)
install -m 0755 bin/conductor-provisioner /usr/local/bin/conductor-provisioner

useradd --system --no-create-home --home-dir /var/lib/conductor-provisioner \
  --shell /usr/sbin/nologin conductor-provisioner
```

conductor's user must exist and its group must be `conductor` (the socket
is created with that group).

## 2. Delegated account

Create the account and delegate the managed OUs as
[delegation.md](delegation.md) describes. The password ends up in
`/etc/conductor-provisioner/credentials/account-password` (root, 0600).

## 3. Configuration and credentials

```sh
install -d -m 0750 -o root -g conductor-provisioner /etc/conductor-provisioner
install -m 0640 -o root -g conductor-provisioner provisioner.toml.example \
  /etc/conductor-provisioner/provisioner.toml
install -m 0644 domain-ca.pem /etc/conductor-provisioner/domain-ca.pem

# The state key (keys the audit chain); keep a copy with your backups:
# without it the audit log can no longer be verified.
umask 077
openssl rand -hex 32 > /etc/conductor-provisioner/credentials/state-key
chmod 0700 /etc/conductor-provisioner/credentials
chmod 0600 /etc/conductor-provisioner/credentials/*
```

Edit `provisioner.toml` ([config.md](config.md)): realm, CA, the account
name, the scope OUs, and conductor's role group SIDs in
`extra_group_sids`. The file is checked at start; unknown keys and values
out of range stop the service.

## 4. Units

```sh
install -m 0644 deploy/systemd/conductor-provisioner.service \
  deploy/systemd/conductor-provisioner-api.socket /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now conductor-provisioner-api.socket conductor-provisioner.service
journalctl -u conductor-provisioner.service   # "signed in to the directory"
```

systemd hands the credentials to the service (`LoadCredential=`), creates
`/var/lib/conductor-provisioner` (0700) and the socket
`/run/conductor-provisioner/api.sock` (owner `conductor-provisioner`,
group `conductor`, 0660). The service admits only the users in
`api.allowed_users`.

## 5. conductor

In conductor's configuration enable the provisioner section with the same
socket path; conductor's pages then show, per user, whether an invitation
or a reset is possible and why not.

## Checks

```sh
conductor-provisioner healthcheck
sudo conductor-provisioner status       # reads the credentials from /etc/conductor-provisioner/credentials
sudo conductor-provisioner audit verify
```

## Uninstall

Stop and disable both units, remove the binary, `/etc/conductor-provisioner`
and `/var/lib/conductor-provisioner`, then remove the delegation entries
(`samba-tool dsacl delete` with the same SDDL) and disable or delete the
account.
