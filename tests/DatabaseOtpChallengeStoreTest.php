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
use Componenta\Identity\Uuid;
use PHPUnit\Framework\TestCase;

final class DatabaseOtpChallengeStoreTest extends TestCase
{
    public function testSuccessfulCodeIsSingleUse(): void
    {
        self::requireSqlite();
        $manager = self::manager(new OtpConfig(resendCooldownSeconds: 0));
        $issue = $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aaa'),
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            new OtpPurpose('authentication'),
            new OtpChannel('email'),
            '018f6d5d-3f7a-7a9b-8c2f-123456789def',
        );

        self::assertSame(
            OtpVerificationStatus::Verified,
            $manager->verify(
                $issue->challenge->uuid,
                $issue->challenge->purpose,
                $issue->challenge->binding,
                $issue->code,
            )->status,
        );
        self::assertSame(
            OtpVerificationStatus::Invalid,
            $manager->verify(
                $issue->challenge->uuid,
                $issue->challenge->purpose,
                $issue->challenge->binding,
                $issue->code,
            )->status,
        );
    }

    public function testAggregateFailuresSurviveNewChallenge(): void
    {
        self::requireSqlite();
        $config = new OtpConfig(
            maxAttempts: 5,
            resendCooldownSeconds: 0,
            aggregateFailureLimit: 2,
        );
        $manager = self::manager($config);
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $purpose = new OtpPurpose('authentication');
        $channel = new OtpChannel('email');
        $binding = '018f6d5d-3f7a-7a9b-8c2f-123456789def';
        $first = $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aa1'),
            $subject,
            $purpose,
            $channel,
            $binding,
        );

        self::assertSame(
            OtpVerificationStatus::Invalid,
            $manager->verify(
                $first->challenge->uuid,
                $purpose,
                $binding,
                str_repeat('0', $config->digits),
            )->status,
        );

        $second = $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aa2'),
            $subject,
            $purpose,
            $channel,
            $binding,
        );

        self::assertSame(
            OtpVerificationStatus::RateLimited,
            $manager->verify(
                $second->challenge->uuid,
                $purpose,
                $binding,
                str_repeat('0', $config->digits),
            )->status,
        );
        self::assertSame(
            OtpVerificationStatus::RateLimited,
            $manager->verify(
                $second->challenge->uuid,
                $purpose,
                $binding,
                $second->code,
            )->status,
        );
    }

    public function testResendCooldownCannotBeBypassedWithNewBinding(): void
    {
        self::requireSqlite();
        $manager = self::manager(new OtpConfig(
            resendCooldownSeconds: 30,
        ));
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $purpose = new OtpPurpose('authentication');
        $channel = new OtpChannel('email');

        $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aa1'),
            $subject,
            $purpose,
            $channel,
            'binding-a',
        );

        $this->expectException(OtpIssueThrottledException::class);

        $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aa2'),
            $subject,
            $purpose,
            $channel,
            'binding-b',
        );
    }

    public function testIssueBudgetSurvivesDifferentBindings(): void
    {
        self::requireSqlite();
        $manager = self::manager(new OtpConfig(
            resendCooldownSeconds: 0,
            maxIssuesPerWindow: 2,
            issueWindowSeconds: 3600,
        ));
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $purpose = new OtpPurpose('authentication');
        $channel = new OtpChannel('email');

        foreach ([
            ['018f6d5d-3f7a-7a9b-8c2f-123456789aa1', 'binding-a'],
            ['018f6d5d-3f7a-7a9b-8c2f-123456789aa2', 'binding-b'],
        ] as [$challenge, $binding]) {
            $manager->issue(
                Uuid::fromString($challenge),
                $subject,
                $purpose,
                $channel,
                $binding,
            );
        }

        $this->expectException(OtpIssueThrottledException::class);

        $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aa3'),
            $subject,
            $purpose,
            $channel,
            'binding-c',
        );
    }

    public function testResendCooldownIsSerialized(): void
    {
        self::requireSqlite();
        $manager = self::manager(new OtpConfig(
            resendCooldownSeconds: 30,
        ));
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $purpose = new OtpPurpose('authentication');
        $channel = new OtpChannel('email');
        $binding = '018f6d5d-3f7a-7a9b-8c2f-123456789def';

        $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aa1'),
            $subject,
            $purpose,
            $channel,
            $binding,
        );

        $this->expectException(OtpIssueThrottledException::class);

        $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aa2'),
            $subject,
            $purpose,
            $channel,
            $binding,
        );
    }

    private static function manager(OtpConfig $config): OtpChallengeManager
    {
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');

        return new OtpChallengeManager(
            new DatabaseOtpChallengeStore(
                SqliteDatabaseFixture::create(),
                $clock,
            ),
            new OtpCodeGenerator(),
            new OtpCodeMac(str_repeat('k', 32)),
            $clock,
            $config,
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
