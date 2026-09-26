<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;

final readonly class OtpPayload
{
    public function __construct(
        public UuidInterface $challengeId,
        #[\SensitiveParameter]
        public string $code,
        public OtpPurpose $purpose,
        public string $binding,
    ) {
        if (
            $binding === ''
            || strlen($binding) > 256
            || preg_match('/[\x00-\x1F\x7F]/', $binding) === 1
        ) {
            throw new \InvalidArgumentException('OTP binding is invalid.');
        }
    }
}
