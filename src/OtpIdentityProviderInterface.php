<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\IdentityInterface;

interface OtpIdentityProviderInterface
{
    public function findByIdentity(string $identity): ?IdentityInterface;
}
