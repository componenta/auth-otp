<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

final readonly class OtpChannel implements \Stringable
{
    public function __construct(public string $value)
    {
        if (preg_match('/\A[a-z][a-z0-9._-]{0,63}\z/D', $value) !== 1) {
            throw new \InvalidArgumentException('OTP channel is invalid.');
        }
    }

    #[\Override]
    public function __toString(): string
    {
        return $this->value;
    }
}
