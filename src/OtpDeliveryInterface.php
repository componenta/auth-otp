<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

interface OtpDeliveryInterface
{
    public function send(
        string $destination,
        OtpChallenge $challenge,
        #[\SensitiveParameter]
        string $code,
    ): void;
}
