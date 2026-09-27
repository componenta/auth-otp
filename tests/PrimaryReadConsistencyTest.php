<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\DatabaseOtpChallengeStore;
use Componenta\Auth\Otp\OtpChallenge;
use Componenta\Auth\Otp\OtpChannel;
use Componenta\Auth\Otp\OtpConfig;
use Componenta\Auth\Otp\OtpIssueThrottledException;
use Componenta\Auth\Otp\OtpPurpose;
use Componenta\Auth\Otp\OtpVerificationStatus;
use Componenta\Auth\Otp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\TestCase;

final class PrimaryReadConsistencyTest extends TestCase
{
    public function testReplicaLagCannotBypassResendCooldown(): void
    {
        [$primary, , $split] = $this->databases();
        $subject = (new UuidFactory())->generate();
        $config = new OtpConfig();
        $this->store($primary)->issue($this->challenge($subject), str_repeat('a', 64), $config);
        $this->expectException(OtpIssueThrottledException::class);
        $this->store($split)->issue($this->challenge($subject), str_repeat('a', 64), $config);
    }

    public function testReplicaLagCannotBypassIssueBudget(): void
    {
        [$primary, , $split] = $this->databases();
        $subject = (new UuidFactory())->generate();
        $config = new OtpConfig(resendCooldownSeconds: 0, maxIssuesPerWindow: 1);
        $this->store($primary)->issue($this->challenge($subject), str_repeat('a', 64), $config);
        $this->expectException(OtpIssueThrottledException::class);
        $this->store($split)->issue($this->challenge($subject), str_repeat('a', 64), $config);
    }

    public function testReplicaLagCannotBypassAggregateFailureBudget(): void
    {
        [$primary, $replica, $split] = $this->databases();
        $challenge = $this->challenge((new UuidFactory())->generate());
        $config = new OtpConfig(aggregateFailureLimit: 1);
        $this->store($primary)->issue($challenge, str_repeat('a', 64), $config);
        foreach (['auth_otp_challenges', 'auth_otp_failure_budgets'] as $table) {
            foreach ($primary->select()->from($table)->run()->fetchAll() as $row) {
                $replica->insert($table)->values($row)->run();
            }
        }
        self::assertSame(OtpVerificationStatus::RateLimited, $this->store($primary)->verify($challenge->uuid, $challenge->binding, str_repeat('b', 64), $config)->status);
        self::assertSame(OtpVerificationStatus::RateLimited, $this->store($split)->verify($challenge->uuid, $challenge->binding, str_repeat('a', 64), $config)->status);
    }

    public function testBudgetsAndAttemptsRespectDatabasePrefix(): void
    {
        [$database] = $this->databases();
        $schema = file_get_contents(dirname(__DIR__) . '/resources/schema/sqlite.sql');
        self::assertIsString($schema);
        foreach (array_filter(array_map('trim', explode(';', str_replace('auth_', 'tenant_auth_', $schema)))) as $sql) {
            $database->execute($sql);
        }
        $store = $this->store($database->withPrefix('tenant_'));
        $challenge = $this->challenge((new UuidFactory())->generate());
        $config = new OtpConfig();
        $store->issue($challenge, str_repeat('a', 64), $config);
        self::assertSame(OtpVerificationStatus::Invalid, $store->verify($challenge->uuid, $challenge->binding, str_repeat('b', 64), $config)->status);
        self::assertSame(OtpVerificationStatus::Verified, $store->verify($challenge->uuid, $challenge->binding, str_repeat('a', 64), $config)->status);
    }

    private function challenge(UuidInterface $subject): OtpChallenge
    {
        $now = new \DateTimeImmutable('2030-01-01T00:00:00+00:00');
        return new OtpChallenge((new UuidFactory())->generate(), $subject, new OtpPurpose('authentication'), new OtpChannel('email'), 'binding', $now, $now->modify('+300 seconds'));
    }

    private function store(DatabaseInterface $database): DatabaseOtpChallengeStore
    {
        return new DatabaseOtpChallengeStore($database, new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'));
    }

    /** @return array{DatabaseInterface, DatabaseInterface, DatabaseInterface} */
    private function databases(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $primary = SqliteDatabaseFixture::create();
        $replica = SqliteDatabaseFixture::create();
        return [$primary, $replica, new Database('split', '', $primary->getDriver(DatabaseInterface::WRITE), $replica->getDriver(DatabaseInterface::READ))];
    }
}
