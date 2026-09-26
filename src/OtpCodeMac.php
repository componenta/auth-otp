<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;

final readonly class OtpCodeMac
{
    public function __construct(
        #[\SensitiveParameter]
        private string $key,
    ) {
        if (strlen($this->key) < 32 || strlen($this->key) > 4096) {
            throw new \InvalidArgumentException(
                'OTP MAC key must contain between 32 and 4096 bytes.',
            );
        }
    }

    public function calculate(
        UuidInterface $challengeId,
        OtpPurpose $purpose,
        #[\SensitiveParameter]
        string $code,
    ): string {
        return hash_hmac(
            'sha256',
            "componenta-auth-otp-v1\0"
                . $challengeId->toString()
                . "\0"
                . $purpose->value
                . "\0"
                . $code,
            $this->key,
        );
    }
}
