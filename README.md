# Componenta Auth OTP

Generic one-time-code challenges for Componenta Auth 4.

OTP is a proof mechanism, not an email-login package. Purpose and channel are
bounded extensible identifiers. Browser login binds the challenge to a
short-lived pre-authentication transaction; reauthentication binds it to the
current public AuthSession UUID.

Security properties:

- CSPRNG numeric codes: 4-8 digits when explicitly configured, six digits by default; for new deployments prefer six or more and retain bounded abuse limits;
- HMAC-SHA-256 verifier with challenge/purpose domain separation;
- plaintext code is never persisted;
- single-use atomic verification;
- per-challenge attempt limit;
- aggregate subject+purpose failure budget survives resend/new challenge;
- resend cooldown;
- generic public invalid-code denial;
- channel-specific evidence never upgrades itself to MFA/phishing resistance.

OTP payloads and issued codes redact the code in JSON and `var_dump` output;
the MAC calculator also redacts its key from `var_dump`. Delivery adapters
must explicitly read `OtpIssue::$code` to send a code. Generic serialization
is not a delivery format.

Revoking a challenge, including after a delivery failure, invalidates its code
while retaining the issuance history for cooldown and issuance-window limits.
Cleanup removes that history only after the maximum supported window has ended.

A successful proof resets the subject+purpose failure budget in place. The row
also coordinates concurrent issuance and verification, so it is retained after
success instead of being deleted while another operation is acquiring its lock.
The SQL lock ends with the transaction. Storage retains one budget row per used
subject+purpose pair, containing counters and coordination state, not OTP codes;
challenge cleanup does not prune these rows.

A correct code is accepted only if its claim completes before the challenge
deadline, including transaction commit. A claim that finishes at or after expiry
is rejected and stays consumed; database or clock exceptions propagate.

## Requirements

PHP 8.4 or newer and the coordinated Componenta Auth 4 dependencies:
`componenta/auth ^4.0.0`, `componenta/auth-session ^2.0.0` and
`componenta/auth-session-http ^3.0.0`. The browser transport uses
`componenta/http-csrf-middleware ^4.0.0`. Unsafe CSRF-protected requests require
valid Origin/Referer evidence and an admitted CSRF token.

Upgrade these packages together. Session issuance uses the shared Componenta
Auth session APIs. See [CHANGELOG.md](CHANGELOG.md) for migration details.
