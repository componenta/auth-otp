<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Otp\Denied\InvalidCode;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class OtpLoginVerifyHandler implements RequestHandlerInterface
{
    public function __construct(
        private OtpExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private PreAuthenticationConsumer $preAuthentication,
        private PreAuthenticationGrantPublisher $preAuthenticationPublisher,
        private AuthenticatedSessionIssuer $sessionIssuer,
        private AuthSessionGrantPublisher $sessionPublisher,
        private SessionMetadataExtractorInterface $metadata,
        private DeniedResponseFactoryInterface $deniedResponses,
        private ResponseFactoryInterface $responses,
        private OtpPurpose $purpose = new OtpPurpose('authentication'),
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $submission = $this->extractor->extract($request);
        $preAuthentication = $this->preAuthentication->verify($request);

        if ($preAuthentication === null) {
            return $this->deniedResponses->create(new InvalidCode());
        }

        // Prepare the success response before the one-time code can be consumed.
        $response = $this->preAuthenticationPublisher->clear(
            $this->responses->createResponse(204),
        );
        $result = $this->authenticator->attempt(
            new OtpPayload(
                $submission->challengeId,
                $submission->code,
                $this->purpose,
                $preAuthentication->uuid->toString(),
            ),
            new Context(),
        );

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponses->create($result->subject);
        }

        $evidence = $result->evidence
            ?? throw new \LogicException(
                'Successful OTP authentication must contain evidence.',
            );

        if ($this->preAuthentication->consume($request) === null) {
            return $this->preAuthenticationPublisher->clear(
                $this->deniedResponses->create(new InvalidCode()),
            );
        }

        $grant = $this->sessionIssuer->issue(
            $result->subject,
            $evidence,
            $this->metadata->extract($request),
        );

        if ($grant instanceof DeniedReasonInterface) {
            return $this->preAuthenticationPublisher->clear($this->deniedResponses->create($grant));
        }

        return $this->sessionPublisher->publish(
            $request,
            $response,
            $grant,
        );
    }
}
