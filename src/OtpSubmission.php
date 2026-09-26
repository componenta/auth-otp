<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;

final readonly class OtpSubmission implements \JsonSerializable
{
    public function __construct(
        public UuidInterface $challengeId,
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
            'challengeId' => $this->challengeId->toString(),
            'code' => '[REDACTED]',
        ];
    }

    /** @return array{challengeId: string, code: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
