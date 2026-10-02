# One-time owner authorization

The public builder cannot automatically read a separate private repository. The
owner must grant scoped access in GitHub settings; this configuration is not a
request to publish the app source or to change any billing plan.

## 1. Private source access (needed even for native validation)
Choose one of these equivalent access methods:

- Existing read-only deploy key: private repository Settings > Deploy keys contains
  the public half, without Allow write access. Store its private half in the public
  builder's Actions secret named `EDUCATION_SOURCE_SSH_KEY`.
- Fine-grained token: limit Repository access to `datagram-education` only, with
  Contents: Read-only (Metadata is read-only automatically) and a short expiry.
  Store it in the public builder's Actions secret named `EDUCATION_SOURCE_TOKEN`.

Create the secret in `datagram-education-ios-build` > Settings > Secrets and
variables > Actions > New repository secret. Do not use Variables. Do not send
the token or private key in chat. The workflow supports either method and fails
closed when neither is present. No broad all-repository personal token is required.

## 2. Existing Apple identity (needed only for TestFlight upload)
Use the same valid distribution identity used for the owner's existing apps, but
use the original Education App Store profile, not the Golden Army profile:

| Actions secret | Required value |
| --- | --- |
| IOS_CERTIFICATE_BASE64 | Base64 of the existing Apple Distribution .p12, including its private key |
| IOS_CERTIFICATE_PASSWORD | Password of that existing .p12 |
| IOS_PROVISIONING_PROFILE_BASE64 | Base64 of the App Store profile for com.datagram.education |
| ASC_PRIVATE_KEY | Existing authorized App Store Connect team API .p8 contents, not the APNs key |
| ASC_KEY_ID | That App Store Connect API key's Key ID |
| ASC_ISSUER_ID | Its team Issuer ID |

No new Apple certificate is created or existing certificate revoked by this workflow.
Existing credentials are not copied across repositories by this setup. Installing
these encrypted secrets is an owner-side configuration step.

## 3. Manual run
Actions > Education iOS validation and TestFlight > Run workflow.
Use the full approved source commit, never a mutable branch or unreviewed PR.
Select `validate` to test native iPhone/iPad only, or `testflight` for validation,
signing and internal upload. Missing signing settings stop before an expensive build.

A passing Public pipeline contract tests run tests the orchestration only. A passing
runner check proves macOS availability only. Neither means the app is in TestFlight.

Official references: GitHub managing personal access tokens, deploy keys and Actions
secrets; Apple App Store Connect generating tokens and listing builds documentation.
