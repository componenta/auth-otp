<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Identity\UuidFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class OtpLoginRequestHandler implements RequestHandlerInterface
{
    public function __construct(
        private PreAuthenticationManagerInterface $preAuthentication,
        private PreAuthenticationGrantPublisher $publisher,
        private OtpRequestQueueInterface $queue,
        private UuidFactoryInterface $uuids,
        private ResponseFactoryInterface $responses,
        private OtpPurpose $purpose = new OtpPurpose('authentication'),
        private OtpChannel $channel = new OtpChannel('email'),
        private string $identityField = 'identity',
        private int $preAuthenticationTtlSeconds = 600,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $body = $request->getParsedBody();
        $identity = is_array($body)
            ? ($body[$this->identityField] ?? null)
            : null;

        if (
            !is_string($identity)
            || $identity === ''
            || strlen($identity) > 320
            || trim($identity) !== $identity
            || preg_match('/[\x00-\x1F\x7F]/', $identity) === 1
        ) {
            return $this->json(400, ['error' => 'invalid_identity']);
        }

        $challengeId = $this->uuids->generate();
        $response = $this->json(200, [
            'challenge_id' => $challengeId->toString(),
            'message' => 'If the account exists, a code has been sent.',
        ]);
        $grant = $this->preAuthentication->create(
            $this->preAuthenticationTtlSeconds,
        );
        $response = $this->publisher->publish($response, $grant);
        $work = new OtpRequest(
            challengeId: $challengeId,
            identity: $identity,
            purpose: $this->purpose,
            channel: $this->channel,
            binding: $grant->transaction->uuid->toString(),
        );

        try {
            $this->queue->enqueue($work);
        } catch (\Throwable $exception) {
            $this->preAuthentication->consume(
                $grant->credential,
                $grant->requestToken,
            );
            throw $exception;
        }

        return $response;
    }

    /** @param array<string, mixed> $payload */
    private function json(int $status, array $payload): ResponseInterface
    {
        $response = $this->responses->createResponse($status);
        $response->getBody()->write(
            json_encode($payload, JSON_THROW_ON_ERROR),
        );

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
