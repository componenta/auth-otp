CREATE TABLE auth_otp_failure_budgets (
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    purpose VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    failures INT UNSIGNED NOT NULL DEFAULT 0,
    window_started_at DATETIME(6) NOT NULL,
    lock_version BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_uuid, purpose)
) ENGINE=InnoDB;

CREATE TABLE auth_otp_challenges (
    uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    purpose VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    channel VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    binding VARCHAR(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    verifier CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    attempts INT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts INT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    consumed_at DATETIME(6) NULL,
    INDEX idx_auth_otp_binding (
        subject_uuid,
        purpose,
        binding,
        created_at
    ),
    INDEX idx_auth_otp_cleanup (expires_at, consumed_at)
) ENGINE=InnoDB;
