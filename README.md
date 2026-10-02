# Datagram Education iOS build orchestration

This public repository contains workflow definitions, signing orchestration and
synthetic tests only. The app source stays in the private `datagram-education`
repository. No application source, signing credentials or raw IPA is published here.

## Verified / not yet verified
The original standard macOS availability check succeeded (run 37017550611).
The signing safeguards have synthetic unit tests; these do not establish native
application success or TestFlight delivery. Source-access and Apple-signing Actions
secrets must be configured by the owner before the application workflow can run.
They have not been installed by the setup described here.

## Workflows
- `runner-check.yml`: source-free macOS availability check.
- `workflow-contract.yml`: tests public signing guards with synthetic data, no secrets.
- `ios-build.yml`: owner-only, exact-private-commit iOS validation. Select `testflight`
  to sign and upload only after all iPhone/iPad native checks pass.

The upload workflow validates the existing Education App Store provisioning profile,
its certificate/team/push entitlement, expiration and app identity. It checks Apple
for a new build number, creates a signed IPA, validates it, then uploads to App Store
Connect. It does not request external beta review, public App Store review or release.
A successful upload is explicitly distinguished from Apple processing completion.

Public runs do not publish private app caches, source logs, simulator screenshots
or unencrypted binaries. Failed native tests cannot be replaced by a successful
runner-availability or unit-test result. No production website host is used to build.

See `SETUP.md` for the one-time owner-controlled configuration. Never paste secret
values into an issue, chat, README, workflow YAML or repository variable.
