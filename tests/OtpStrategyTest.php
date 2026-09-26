<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Context;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Otp\DatabaseOtpChallengeStore;
use Componenta\Auth\Otp\OtpChallengeManager;
use Componenta\Auth\Otp\OtpChannel;
use Componenta\Auth\Otp\OtpCodeGenerator;
use Componenta\Auth\Otp\OtpCodeMac;
use Componenta\Auth\Otp\OtpConfig;
use Componenta\Auth\Otp\OtpPayload;
use Componenta\Auth\Otp\OtpPurpose;
use Componenta\Auth\Otp\OtpStrategy;
use Componenta\Auth\Otp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class OtpStrategyTest extends TestCase
{
    public function testVerifiedChallengeCarriesChannelSpecificEvidence(): void
    {
        self::requireSqlite();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $manager = new OtpChallengeManager(
            new DatabaseOtpChallengeStore(
                SqliteDatabaseFixture::create(),
                $clock,
            ),
            new OtpCodeGenerator(),
            new OtpCodeMac(str_repeat('k', 32)),
            $clock,
            new OtpConfig(resendCooldownSeconds: 0),
        );
        $identity = new OtpIdentityFixture();
        $challengeId = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789aaa',
        );
        $purpose = new OtpPurpose('authentication');
        $binding = '018f6d5d-3f7a-7a9b-8c2f-123456789def';
        $issue = $manager->issue(
            $challengeId,
            $identity->uuid,
            $purpose,
            new OtpChannel('email'),
            $binding,
        );
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);

        $result = (new OtpStrategy($manager, $identities))->attempt(
            new OtpPayload(
                $challengeId,
                $issue->code,
                $purpose,
                $binding,
            ),
            new Context(),
        );

        self::assertSame($identity, $result->subject);
        self::assertSame(['otp.email'], $result->evidence?->methods);
        self::assertSame(
            ['one_time_code'],
            $result->evidence?->capabilities,
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}

final class OtpIdentityFixture implements IdentityInterface
{
    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}
