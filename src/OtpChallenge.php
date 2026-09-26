<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class OtpChallenge
{
    public function __construct(
        public UuidInterface $uuid,
        public UuidInterface $subjectId,
        public OtpPurpose $purpose,
        public OtpChannel $channel,
        public string $binding,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $expiresAt,
        public int $attempts = 0,
        public ?DateTimeImmutable $consumedAt = null,
    ) {
        if (
            $binding === ''
            || strlen($binding) > 256
            || preg_match('/[\x00-\x1F\x7F]/', $binding) === 1
        ) {
            throw new \InvalidArgumentException('OTP binding is invalid.');
        }

        if ($expiresAt <= $createdAt || $attempts < 0) {
            throw new \InvalidArgumentException(
                'OTP challenge lifecycle is invalid.',
            );
        }
    }
}
