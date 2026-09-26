<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

final readonly class OtpChallengeManager
{
    public function __construct(
        private OtpChallengeStoreInterface $store,
        private OtpCodeGenerator $codes,
        private OtpCodeMac $mac,
        private ClockInterface $clock,
        private OtpConfig $config = new OtpConfig(),
    ) {}

    public function issue(
        UuidInterface $challengeId,
        UuidInterface $subjectId,
        OtpPurpose $purpose,
        OtpChannel $channel,
        string $binding,
    ): OtpIssue {
        $code = $this->codes->generate($this->config->digits);
        $now = $this->now();
        $challenge = new OtpChallenge(
            uuid: $challengeId,
            subjectId: $subjectId,
            purpose: $purpose,
            channel: $channel,
            binding: $binding,
            createdAt: $now,
            expiresAt: $now->modify(
                sprintf('+%d seconds', $this->config->ttlSeconds),
            ),
        );
        $this->store->issue(
            $challenge,
            $this->mac->calculate($challengeId, $purpose, $code),
            $this->config,
        );

        return new OtpIssue($challenge, $code);
    }

    public function verify(
        UuidInterface $challengeId,
        OtpPurpose $purpose,
        string $binding,
        #[\SensitiveParameter]
        string $code,
    ): OtpVerification {
        if (
            preg_match(
                sprintf('/\A[0-9]{%d}\z/D', $this->config->digits),
                $code,
            ) !== 1
        ) {
            return OtpVerification::invalid();
        }

        return $this->store->verify(
            $challengeId,
            $binding,
            $this->mac->calculate($challengeId, $purpose, $code),
            $this->config,
        );
    }

    public function revoke(UuidInterface $challengeId): void
    {
        $this->store->revoke($challengeId);
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }
}
