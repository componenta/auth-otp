<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

enum OtpVerificationStatus: string
{
    case Verified = 'verified';
    case Invalid = 'invalid';
    case RateLimited = 'rate_limited';
}
