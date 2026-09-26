<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

final readonly class OtpRequestProcessor
{
    public function __construct(
        private OtpIdentityProviderInterface $identities,
        private OtpChallengeManager $challenges,
        private OtpDeliveryInterface $delivery,
    ) {}

    public function process(OtpRequest $request): void
    {
        $identity = $this->identities->findByIdentity($request->identity);

        if ($identity === null) {
            return;
        }

        $issue = $this->challenges->issue(
            $request->challengeId,
            $identity->uuid,
            $request->purpose,
            $request->channel,
            $request->binding,
        );

        try {
            $this->delivery->send(
                $request->identity,
                $issue->challenge,
                $issue->code,
            );
        } catch (\Throwable $exception) {
            $this->challenges->revoke($issue->challenge->uuid);
            throw $exception;
        }
    }
}
