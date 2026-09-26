CREATE TABLE auth_otp_failure_budgets (
    subject_uuid UUID NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0,
    window_started_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    lock_version BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_uuid, purpose)
);

CREATE TABLE auth_otp_challenges (
    uuid UUID PRIMARY KEY,
    subject_uuid UUID NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    channel VARCHAR(64) NOT NULL,
    binding VARCHAR(256) NOT NULL,
    verifier CHAR(64) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    consumed_at TIMESTAMP(6) WITHOUT TIME ZONE NULL
);

CREATE INDEX idx_auth_otp_binding
    ON auth_otp_challenges(subject_uuid, purpose, binding, created_at);
CREATE INDEX idx_auth_otp_cleanup
    ON auth_otp_challenges(expires_at, consumed_at);
