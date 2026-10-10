# Componenta Auth OTP

Generic one-time-code challenges for Componenta Auth 3.

OTP is a proof mechanism, not an email-login package. Purpose and channel are
bounded extensible identifiers. Browser login binds the challenge to a
short-lived pre-authentication transaction; reauthentication binds it to the
current public AuthSession UUID.

Security properties:

- CSPRNG 6-8 digit codes;
- HMAC-SHA-256 verifier with challenge/purpose domain separation;
- plaintext code is never persisted;
- single-use atomic verification;
- per-challenge attempt limit;
- aggregate subject+purpose failure budget survives resend/new challenge;
- resend cooldown;
- generic public invalid-code denial;
- channel-specific evidence never upgrades itself to MFA/phishing resistance.

## Version 2 compatibility

Version 2.0.0 requires `componenta/auth-session-http ^2.0.1`. Its browser
security contract uses `componenta/http-csrf-middleware ^3.0`, which validates
Origin/Referer on unsafe requests and rejects missing origin metadata by
default. Upgrade the session HTTP and CSRF packages together; do not disable
origin validation to preserve older clients.

See [the changelog](CHANGELOG.md) for migration details. Session issuance
continues to use the shared Componenta Auth session APIs; this package does
not create an independent session or CSRF stack.
