<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Otp\Denied\InvalidCode;

final readonly class OtpStrategy implements AuthenticationStrategyInterface
{
    public function __construct(
        private OtpChallengeManager $challenges,
        private IdentityProviderInterface $identities,
    ) {}

    #[\Override]
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return $payload instanceof OtpPayload;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        if (!$payload instanceof OtpPayload) {
            return new AuthenticationResult(new InvalidCode());
        }

        $verification = $this->challenges->verify(
            $payload->challengeId,
            $payload->purpose,
            $payload->binding,
            $payload->code,
        );

        if (
            $verification->status !== OtpVerificationStatus::Verified
            || $verification->subjectId === null
            || $verification->channel === null
        ) {
            return new AuthenticationResult(new InvalidCode());
        }

        $identity = $this->identities->findByUuid(
            $verification->subjectId,
        );

        if (
            $identity === null
            || !$identity->uuid->equals($verification->subjectId)
        ) {
            return new AuthenticationResult(new InvalidCode());
        }

        return new AuthenticationResult(
            subject: $identity,
            evidence: new AuthenticationEvidence(
                methods: ['otp.' . $verification->channel->value],
                capabilities: ['one_time_code'],
            ),
        );
    }
}
