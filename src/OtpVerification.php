<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;

final readonly class OtpVerification
{
    private function __construct(
        public OtpVerificationStatus $status,
        public ?UuidInterface $subjectId = null,
        public ?OtpChannel $channel = null,
    ) {}

    public static function verified(
        UuidInterface $subjectId,
        OtpChannel $channel,
    ): self {
        return new self(
            OtpVerificationStatus::Verified,
            $subjectId,
            $channel,
        );
    }

    public static function invalid(): self
    {
        return new self(OtpVerificationStatus::Invalid);
    }

    public static function rateLimited(): self
    {
        return new self(OtpVerificationStatus::RateLimited);
    }
}
