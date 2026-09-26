<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Denied;

use Componenta\Auth\DeniedReasonInterface;

final class InvalidCode implements DeniedReasonInterface
{
    public string $code { get => 'invalid_code'; }

    /** @var array<string, mixed> */
    public array $attributes { get => []; }
}
