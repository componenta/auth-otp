CREATE TABLE auth_otp_failure_budgets (
    subject_uuid TEXT NOT NULL,
    purpose TEXT NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    window_started_at TEXT NOT NULL,
    lock_version INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_uuid, purpose)
);

CREATE TABLE auth_otp_challenges (
    uuid TEXT PRIMARY KEY,
    subject_uuid TEXT NOT NULL,
    purpose TEXT NOT NULL,
    channel TEXT NOT NULL,
    binding TEXT NOT NULL,
    verifier TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT NULL
);

CREATE INDEX auth_otp_subject_purpose_binding
    ON auth_otp_challenges(subject_uuid, purpose, binding, created_at);
CREATE INDEX auth_otp_cleanup
    ON auth_otp_challenges(expires_at, consumed_at);
