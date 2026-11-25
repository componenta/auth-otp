<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\DatabaseOtpChallengeStore;
use Componenta\Auth\Otp\OtpChallengeManager;
use Componenta\Auth\Otp\OtpChannel;
use Componenta\Auth\Otp\OtpCodeGenerator;
use Componenta\Auth\Otp\OtpCodeMac;
use Componenta\Auth\Otp\OtpConfig;
use Componenta\Auth\Otp\OtpIssueThrottledException;
use Componenta\Auth\Otp\OtpPurpose;
use Componenta\Auth\Otp\OtpVerificationStatus;
use Componenta\Auth\Otp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RevocationBudgetRetentionTest extends TestCase
{
    /** @return iterable<string, array{OtpConfig}> */
    public static function issuanceLimits(): iterable
    {
        yield 'issuance window' => [new OtpConfig(resendCooldownSeconds: 0, maxIssuesPerWindow: 1)];
        yield 'resend cooldown' => [new OtpConfig(resendCooldownSeconds: 30)];
    }

    #[DataProvider('issuanceLimits')]
    public function testRevocationPreservesIssuanceLimits(OtpConfig $config): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $store = new DatabaseOtpChallengeStore(SqliteDatabaseFixture::create(), $clock);
        $manager = new OtpChallengeManager($store, new OtpCodeGenerator(), new OtpCodeMac(str_repeat('k', 32)), $clock, $config);
        $uuids = new UuidFactory();
        $subject = $uuids->generate();
        $purpose = new OtpPurpose('authentication');
        $channel = new OtpChannel('email');
        $issue = $manager->issue($uuids->generate(), $subject, $purpose, $channel, 'browser-binding');

        $manager->revoke($issue->challenge->uuid);

        self::assertSame(
            OtpVerificationStatus::Invalid,
            $manager->verify($issue->challenge->uuid, $purpose, 'browser-binding', $issue->code)->status,
        );
        $this->expectException(OtpIssueThrottledException::class);

        $manager->issue($uuids->generate(), $subject, $purpose, $channel, 'another-binding');
    }

    public function testRevokedChallengesAreRetainedUntilTheMaximumIssuanceWindowEnds(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $store = new DatabaseOtpChallengeStore(SqliteDatabaseFixture::create(), $clock);
        $manager = new OtpChallengeManager($store, new OtpCodeGenerator(), new OtpCodeMac(str_repeat('k', 32)), $clock);
        $uuids = new UuidFactory();
        $issue = $manager->issue($uuids->generate(), $uuids->generate(), new OtpPurpose('authentication'), new OtpChannel('email'), 'browser-binding');
        $manager->revoke($issue->challenge->uuid);
        $manager->revoke($issue->challenge->uuid);

        self::assertSame(0, $store->cleanup());
        $clock->advance('+86401 seconds');
        self::assertSame(1, $store->cleanup());
        self::assertSame(0, $store->cleanup());
    }
}
