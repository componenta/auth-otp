<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;

final readonly class OtpPayload implements \JsonSerializable
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

    /** @return array{challengeId: string, code: string, purpose: string, binding: string} */
    public function __debugInfo(): array
    {
        return [
            'challengeId' => $this->challengeId->toString(),
            'code' => '[REDACTED]',
            'purpose' => $this->purpose->value,
            'binding' => $this->binding,
        ];
    }

    /** @return array{challengeId: string, code: string, purpose: string, binding: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
