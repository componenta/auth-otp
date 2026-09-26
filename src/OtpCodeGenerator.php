<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

final readonly class OtpCodeGenerator
{
    public function generate(int $digits): string
    {
        if ($digits < 6 || $digits > 8) {
            throw new \InvalidArgumentException('OTP digits must be 6-8.');
        }

        $max = (10 ** $digits) - 1;

        return str_pad(
            (string) random_int(0, $max),
            $digits,
            '0',
            STR_PAD_LEFT,
        );
    }
}
