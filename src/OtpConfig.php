<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

final readonly class OtpConfig
{
    public function __construct(
        public int $digits = 6,
        public int $ttlSeconds = 300,
        public int $maxAttempts = 5,
        public int $resendCooldownSeconds = 30,
        public int $aggregateFailureLimit = 10,
        public int $aggregateWindowSeconds = 3600,
    ) {
        if ($digits < 6 || $digits > 8) {
            throw new \InvalidArgumentException('OTP digits must be 6-8.');
        }

        if ($ttlSeconds < 30 || $ttlSeconds > 600) {
            throw new \InvalidArgumentException(
                'OTP TTL must be between 30 and 600 seconds.',
            );
        }

        if ($maxAttempts < 1 || $maxAttempts > 20) {
            throw new \InvalidArgumentException(
                'OTP challenge attempts must be between 1 and 20.',
            );
        }

        if (
            $resendCooldownSeconds < 0
            || $resendCooldownSeconds > $ttlSeconds
        ) {
            throw new \InvalidArgumentException(
                'OTP resend cooldown is invalid.',
            );
        }

        if ($aggregateFailureLimit < 1 || $aggregateFailureLimit > 100) {
            throw new \InvalidArgumentException(
                'OTP aggregate failure limit is invalid.',
            );
        }

        if (
            $aggregateWindowSeconds < $ttlSeconds
            || $aggregateWindowSeconds > 86_400
        ) {
            throw new \InvalidArgumentException(
                'OTP aggregate failure window is invalid.',
            );
        }
    }
}
