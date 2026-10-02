# Datagram Education iOS build orchestration

This public repository contains workflow definitions only. Application source
remains in `centerdata58-lang/datagram-education`, which is private.

`runner-check.yml` proves standard macOS runner availability without loading source
or credentials. Run 37017550611 completed successfully on October 2, 2026.

`ios-build.yml` is an owner-triggered native build pipeline pinned to an exact
private-source commit and fixed action revisions. It requires a read-only,
repository-scoped access key stored in the encrypted `EDUCATION_SOURCE_SSH_KEY`
Actions secret. That secret has not yet been configured; the pipeline fails closed
instead of publishing source or substituting a broad personal token.

No pull-request triggers, publicly readable app caches, raw private logs or
unencrypted application artifacts are enabled. Application compilation/testing
output remains on the ephemeral runner and is not published. The runner is not
the production website machine.

The availability check passed; the private-source pipeline and signed TestFlight
delivery have not yet run. Existing Apple signing material has not been moved here.
