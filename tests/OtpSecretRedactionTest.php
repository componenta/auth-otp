<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\OtpChallenge;
use Componenta\Auth\Otp\OtpChannel;
use Componenta\Auth\Otp\OtpCodeMac;
use Componenta\Auth\Otp\OtpIssue;
use Componenta\Auth\Otp\OtpPayload;
use Componenta\Auth\Otp\OtpPurpose;
use Componenta\Identity\Uuid;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class OtpSecretRedactionTest extends TestCase
{
    public function testAuthenticationPayloadRedactsCodeFromJsonAndDebugOutput(): void
    {
        $payload = new OtpPayload(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aaa'),
            '572093',
            new OtpPurpose('authentication'),
            'browser-binding',
        );

        self::assertStringNotContainsString('572093', json_encode($payload, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('572093', self::dump($payload));
        self::assertSame('572093', $payload->code);
    }

    public function testIssuedCodeIsAvailableForDeliveryButRedactedFromJsonAndDebugOutput(): void
    {
        $now = new DateTimeImmutable('2030-01-01T00:00:00Z');
        $issue = new OtpIssue(
            new OtpChallenge(
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aaa'),
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
                new OtpPurpose('authentication'),
                new OtpChannel('email'),
                'browser-binding',
                $now,
                $now->modify('+5 minutes'),
            ),
            '572093',
        );

        self::assertStringNotContainsString('572093', json_encode($issue, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('572093', self::dump($issue));
        self::assertSame('572093', $issue->code);
    }

    public function testCodeMacRedactsItsKeyFromDebugOutput(): void
    {
        $key = str_repeat('synthetic-secret-key-', 2);

        self::assertStringNotContainsString($key, self::dump(new OtpCodeMac($key)));
    }

    private static function dump(object $value): string
    {
        ob_start();

        try {
            var_dump($value);

            return (string) ob_get_contents();
        } finally {
            ob_end_clean();
        }
    }
}
