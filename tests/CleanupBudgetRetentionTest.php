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
use PHPUnit\Framework\TestCase;

final class CleanupBudgetRetentionTest extends TestCase
{
    public function testCleanupCannotResetAnUnfinishedIssueWindow(): void
    {
        [$clock, $store, $manager] = $this->fixture();
        $uuids = new UuidFactory();
        $subject = $uuids->generate();
        $purpose = new OtpPurpose('authentication');
        $channel = new OtpChannel('email');
        $issue = $manager->issue($uuids->generate(), $subject, $purpose, $channel, 'binding');
        $clock->advance('+301 seconds');

        self::assertSame(OtpVerificationStatus::Invalid, $manager->verify($issue->challenge->uuid, $purpose, 'binding', $issue->code)->status);
        self::assertSame(0, $store->cleanup());
        $this->expectException(OtpIssueThrottledException::class);
        $manager->issue($uuids->generate(), $subject, $purpose, $channel, 'new-binding');
    }

    public function testExpiredIssuesEventuallyBecomeCollectible(): void
    {
        [$clock, $store, $manager] = $this->fixture();
        $uuids = new UuidFactory();
        $manager->issue($uuids->generate(), $uuids->generate(), new OtpPurpose('authentication'), new OtpChannel('email'), 'binding');
        $clock->advance('+86401 seconds');
        self::assertSame(1, $store->cleanup());
        self::assertSame(0, $store->cleanup());
    }

    /** @return array{FrozenClock, DatabaseOtpChallengeStore, OtpChallengeManager} */
    private function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $store = new DatabaseOtpChallengeStore(SqliteDatabaseFixture::create(), $clock);
        $manager = new OtpChallengeManager($store, new OtpCodeGenerator(), new OtpCodeMac(str_repeat('k', 32)), $clock, new OtpConfig(resendCooldownSeconds: 0, maxIssuesPerWindow: 1));
        return [$clock, $store, $manager];
    }
}
