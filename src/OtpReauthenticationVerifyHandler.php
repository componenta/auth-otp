<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Otp\Denied\InvalidCode;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\RotationReason;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class OtpReauthenticationVerifyHandler implements
    RequestHandlerInterface
{
    public function __construct(
        private OtpExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private AuthSessionManagerInterface $sessions,
        private AuthSessionGrantPublisher $publisher,
        private DeniedResponseFactoryInterface $deniedResponses,
        private ResponseFactoryInterface $responses,
        private OtpPurpose $purpose = new OtpPurpose('reauthentication'),
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $session = $request->getAttribute(AuthSession::class);
        $currentIdentity = $request->getAttribute(IdentityInterface::class);

        if (
            !$session instanceof AuthSession
            || !$currentIdentity instanceof IdentityInterface
            || !$currentIdentity->uuid->equals($session->subjectId)
        ) {
            return $this->deniedResponses->create(new InvalidCode());
        }

        $submission = $this->extractor->extract($request);
        $response = $this->responses->createResponse(204);
        $result = $this->authenticator->attempt(
            new OtpPayload(
                $submission->challengeId,
                $submission->code,
                $this->purpose,
                $session->uuid->toString(),
            ),
            new Context(),
        );

        if (
            $result->subject instanceof DeniedReasonInterface
            || !$result->subject->uuid->equals($currentIdentity->uuid)
        ) {
            return $result->subject instanceof DeniedReasonInterface
                ? $this->deniedResponses->create($result->subject)
                : $this->deniedResponses->create(new InvalidCode());
        }

        $otpEvidence = $result->evidence
            ?? throw new \LogicException(
                'Successful OTP reauthentication must contain evidence.',
            );
        $evidence = new AuthenticationEvidence(
            methods: array_values(array_unique([
                ...$session->evidence->methods,
                ...$otpEvidence->methods,
            ])),
            capabilities: array_values(array_unique([
                ...$session->evidence->capabilities,
                ...$otpEvidence->capabilities,
            ])),
        );
        $grant = $this->sessions->rotate(
            $session,
            $evidence,
            RotationReason::Reauthentication,
        );

        return $this->publisher->publish($request, $response, $grant);
    }
}
