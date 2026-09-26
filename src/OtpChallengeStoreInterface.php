<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;

interface OtpChallengeStoreInterface
{
    public function issue(
        OtpChallenge $challenge,
        #[\SensitiveParameter]
        string $verifier,
        OtpConfig $config,
    ): void;

    public function verify(
        UuidInterface $challengeId,
        string $binding,
        #[\SensitiveParameter]
        string $verifier,
        OtpConfig $config,
    ): OtpVerification;

    public function revoke(UuidInterface $challengeId): void;

    public function cleanup(int $limit = 1000): int;
}
