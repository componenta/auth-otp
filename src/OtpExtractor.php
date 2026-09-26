<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Identity\Uuid;
use Psr\Http\Message\ServerRequestInterface;

final readonly class OtpExtractor
{
    public function __construct(
        public string $challengeField = 'challenge_id',
        public string $codeField = 'code',
    ) {}

    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): OtpSubmission {
        $body = $request->getParsedBody();

        if (!is_array($body)) {
            throw InvalidPayloadException::invalidField('body');
        }

        $challenge = $body[$this->challengeField] ?? null;
        $code = $body[$this->codeField] ?? null;

        if (!is_string($challenge)) {
            throw InvalidPayloadException::invalidField(
                $this->challengeField,
            );
        }

        try {
            $challengeId = Uuid::fromString($challenge);
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField(
                $this->challengeField,
            );
        }

        if (!is_string($code)) {
            throw InvalidPayloadException::invalidField($this->codeField);
        }

        try {
            return new OtpSubmission($challengeId, $code);
        } catch (\InvalidArgumentException) {
            throw InvalidPayloadException::invalidField($this->codeField);
        }
    }
}
