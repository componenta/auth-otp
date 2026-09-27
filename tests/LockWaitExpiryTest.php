<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\DatabaseOtpChallengeStore;
use Componenta\Auth\Otp\OtpChallenge;
use Componenta\Auth\Otp\OtpChannel;
use Componenta\Auth\Otp\OtpConfig;
use Componenta\Auth\Otp\OtpPurpose;
use Componenta\Auth\Otp\OtpVerificationStatus;
use Componenta\Auth\Otp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerAwareInterface;

final class LockWaitExpiryTest extends TestCase
{
    public static function verifiers(): iterable
    {
        yield 'correct expired proof' => [str_repeat('a', 64)];
        yield 'incorrect expired proof' => [str_repeat('b', 64)];
    }

    #[DataProvider('verifiers')]
    public function testExpiryIsCheckedAfterTheSubjectLockIsAcquired(string $verifier): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $store = new DatabaseOtpChallengeStore($database, $clock);
        $uuids = new UuidFactory();
        $challenge = new OtpChallenge($uuids->generate(), $uuids->generate(), new OtpPurpose('authentication'), new OtpChannel('email'), 'binding', $clock->now(), $clock->now()->modify('+300 seconds'));
        $config = new OtpConfig();
        $store->issue($challenge, str_repeat('a', 64), $config);
        $driver = $database->getDriver(DatabaseInterface::WRITE);
        self::assertInstanceOf(LoggerAwareInterface::class, $driver);
        // Advance time at the SQL lock boundary, modelling a request that waits
        // for another transaction until its proof expires. No sleeps required.
        $logger = new class($clock) extends AbstractLogger {
            public bool $advanced = false;
            public function __construct(private FrozenClock $clock) {}
            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $sql = (string) $message;
                if (!$this->advanced && str_starts_with($sql, 'UPDATE') && str_contains($sql, 'lock_version + 1')) {
                    $this->advanced = true;
                    $this->clock->advance('+301 seconds');
                }
            }
        };
        $driver->setLogger($logger);

        self::assertSame(OtpVerificationStatus::Invalid, $store->verify($challenge->uuid, $challenge->binding, $verifier, $config)->status);
        self::assertTrue($logger->advanced, 'The test must cross the locking boundary.');
        $row = $database->select()->from('auth_otp_challenges')->where('uuid', $challenge->uuid->toString())->run()->fetch();
        self::assertIsArray($row);
        self::assertNull($row['consumed_at']);
        self::assertSame(0, (int) $row['attempts'], 'Expired requests do not spend the live challenge budget.');
    }
}
