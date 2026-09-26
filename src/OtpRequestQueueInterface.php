<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

interface OtpRequestQueueInterface
{
    public function enqueue(OtpRequest $request): void;
}
