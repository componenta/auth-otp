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
