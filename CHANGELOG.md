# Changelog

## Unreleased (3.0.0)

### Fixed

- Reject a correct OTP when its claim finishes at or after expiry, including
  a delayed transaction commit. The claimed code stays consumed.
- Reset the aggregate failure budget without deleting its synchronization row.
  A concurrent valid issuance or verification no longer loses the row between
  its no-op INSERT and lock UPDATE. Keep one row per used subject+purpose pair.

### Dependency compatibility

- Require Componenta Auth 4, Auth Session 2 and Auth Session HTTP 3, including
  the CSRF 4 browser transport. Upgrade the authentication packages together;
  the previous Auth 3 and Session HTTP 2 dependency families are incompatible.
- Require `componenta/identity ^1.1.1` and test with `componenta/clock ^1.2.0`.
- Require `componenta/auth-http ^2.0.0` for the shared credential transport.

## v2.0.1 (2026-10-11)

- Restore configurable **4–8 digit OTP** compatibility for existing consumers;
  the default remains **6 digits** and new deployments should prefer at least
  six with bounded issue, verification and aggregate abuse limits.
- The shared CSPRNG code generator, configuration and challenge verifier now
  agree on the selected code length. No second generator or changed
  challenge/session issuer is introduced.
- Retain auth-session-http ^2.0.1 and CSRF v3 compatibility.
- Test single-use verification and rejection of invalid lengths for 4–8 digits.


## v2.0.0 — coordinated session-http 2 / CSRF v3 migration (2026-10-10)

### Dependency compatibility
- Require `componenta/auth-session-http ^2.0.1` instead of ^1.0.
- Adopt its `componenta/http-csrf-middleware ^3.0` browser security dependency transitively.
- Preserve the existing OTP challenge and login public API; no second session issuer or CSRF implementation is introduced.
- Update the development branch alias to `2.0.x-dev`.

### Migration
- Consumers must upgrade `componenta/auth-session-http` to 2.0.1 or newer within major 2 and use the CSRF v3 family.
- Browser clients must provide permitted Origin/Referer information for unsafe CSRF-protected operations; do not bypass fail-closed verification.
- Upgrade in a coordinated dependency graph; `componenta/auth-session-http` 1.x cannot coexist with this release.
- Validate actual HTTP / session / CSRF interaction on PHP 8.4 and 8.5 before deploying the new stack.

### Verification
- The GitHub release workflow checks Composer metadata, dependency resolution, dependency advisories, PHPStan and PHPUnit on both supported PHP versions before publishing its tag.
