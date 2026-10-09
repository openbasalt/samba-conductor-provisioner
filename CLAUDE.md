# conductor-provisioner: guidelines

Holds the only standing AD write credential of the Samba Conductor family: a
least-privilege account delegated on the managed OUs only. Executes typed
operations for conductor over a Unix socket and enforces its own invariants
(scope, privileged accounts, ceilings, token binding) even if conductor is
compromised.

- Read `../CLAUDE.md` (family rules) and [architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md).
- Go: `make check` (gofmt, vet, staticcheck, govulncheck, `go test -race`). Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).
- Public repository: no roadmap promises, no internal host names, no customer, company or hosting provider names; in prose no em dashes, bold or ellipsis.
- `provapi` is imported by conductor: standard library only, strict decoding, additive changes keep `ProtocolVersion`.
- Tests never write to a real directory: use the in-memory fake in `internal/server`. Lab tests (`-tags lab`) need the `AD_LAB_*` and `PROV_LAB_*` environment.
- Invariants (docs/design.md) are checked on every operation that names a target; a new operation goes through the same registry and checks.
- Password material never reaches logs, the audit log, errors or the state database.
