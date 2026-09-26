<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

final readonly class OtpIssue
{
    public function __construct(
        public OtpChallenge $challenge,
        #[\SensitiveParameter]
        public string $code,
    ) {
        if (preg_match('/\A[0-9]{6,8}\z/D', $code) !== 1) {
            throw new \InvalidArgumentException('OTP code is invalid.');
        }
    }

    /** @return array{challengeId: string, code: string} */
    public function __debugInfo(): array
    {
        return [
            'challengeId' => $this->challenge->uuid->toString(),
            'code' => '[REDACTED]',
        ];
    }
}
