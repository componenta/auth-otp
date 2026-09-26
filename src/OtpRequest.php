<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;

final readonly class OtpRequest
{
    public function __construct(
        public UuidInterface $challengeId,
        public string $identity,
        public OtpPurpose $purpose,
        public OtpChannel $channel,
        public string $binding,
    ) {
        if (
            $identity === ''
            || strlen($identity) > 320
            || trim($identity) !== $identity
            || preg_match('/[\x00-\x1F\x7F]/', $identity) === 1
        ) {
            throw new \InvalidArgumentException(
                'OTP request identity is invalid.',
            );
        }

        if (
            $binding === ''
            || strlen($binding) > 256
            || preg_match('/[\x00-\x1F\x7F]/', $binding) === 1
        ) {
            throw new \InvalidArgumentException(
                'OTP request binding is invalid.',
            );
        }
    }
}
