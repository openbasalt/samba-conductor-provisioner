# Contributing to conductor-provisioner (delegated AD writes for conductor)

Thank you for helping. This repository is one of the Samba Conductor
repositories; each one has its own issues, pull requests and releases:

| Repository | Component |
|---|---|
| [samba-conductor](https://github.com/openbasalt/samba-conductor) | conductor: web administration, self-service, conductor-helper |
| [samba-conductor-idp](https://github.com/openbasalt/samba-conductor-idp) | conductor-idp: OpenID Connect and SAML identity provider |
| [samba-conductor-sync](https://github.com/openbasalt/samba-conductor-sync) | conductor-sync: provisioning to Google Workspace |
| [samba-conductor-provisioner](https://github.com/openbasalt/samba-conductor-provisioner) | conductor-provisioner: delegated AD writes and one-time password links for conductor |
| [samba-conductor-backup](https://github.com/openbasalt/samba-conductor-backup) | conductor-backup: encrypted backups and restore drills |
| [samba-conductor-files](https://github.com/openbasalt/samba-conductor-files) | conductor-files: agent on domain-member file servers |
| [samba-conductor-ad](https://github.com/openbasalt/samba-conductor-ad) | the `ad` Go library shared by the components |

Security problems: do not open an issue, follow [SECURITY.md](SECURITY.md).

## Before you start

- Bugs and small fixes: open a pull request directly, or an issue first if
  you are not sure it is a bug.
- New features, new operations, new dependencies or changes to a security
  rule (what the service may write, which accounts it refuses, ceilings,
  token lifetimes, what is audited): open an issue first to agree on the
  design. This service holds a standing write credential on the directory,
  so its invariants hold even when its only client is compromised.
  Contributions keep that property.

## Development setup

You need Go (the version in `go.mod`; with `GOTOOLCHAIN=auto` the go command
fetches it) and git.

The components are separate Go modules that import each other by their
repository paths (for example `github.com/openbasalt/samba-conductor-ad`).
`go.mod` pins the sibling modules it uses (`samba-conductor-ad`) by version,
so this repository builds and tests on its own:

```sh
git clone https://github.com/openbasalt/samba-conductor-provisioner.git
cd samba-conductor-provisioner
make check      # gofmt, go vet, staticcheck, govulncheck, go test -race
```

To change several repositories together, clone them side by side and use a
Go workspace in the parent directory, so each build uses your local copies
instead of the pinned versions:

```sh
go work init ./samba-conductor-ad ./samba-conductor ./samba-conductor-provisioner
```

The `Makefile` sets `GOWORK=off` by default, so `make check` always checks
the repository against its pinned versions (what CI and a release build
use); run `make check GOWORK=$PWD/../go.work` to check it against the
workspace. After a change in a sibling module is merged, update the pin here
in a separate pull request (the pin must name a commit that is on GitHub):

```sh
GOWORK=off go get github.com/openbasalt/samba-conductor-ad@<commit or tag>
GOWORK=off go mod tidy
```

## Pull requests

- Keep them focused; one topic per pull request.
- `make check` passes. Add or update tests with the change: every invariant
  of the service has a unit test against the in-memory directory, and a
  new operation needs the same.
- The `provapi` package is imported by conductor: keep it free of heavy
  dependencies (standard library only) and follow its versioning rules.
- Code comments, documentation and commit messages in English.
- Do not commit secrets, real host names, addresses or customer data, not
  even in tests: use the lab names (`lab.conductor.test`) and documentation
  addresses (192.0.2.0/24, `example.com`).
- Commit messages: a short summary line prefixed with the area
  (`provapi: ...`, `server: ...`), then what changed and why.

By submitting a contribution you agree that it is licensed under the
Apache License, Version 2.0, this repository's license (see [LICENSE](LICENSE)
and [NOTICE](NOTICE)), as section 5 of that license provides.

## Code of conduct

Be respectful and constructive. The OpenBasalt code of conduct applies to
every repository of the organization.
