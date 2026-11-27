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

final class VerificationExpiryTest extends TestCase
{
    /** @return iterable<string, array{string, int, OtpVerificationStatus}> */
    public static function claimDelays(): iterable
    {
        foreach (['UPDATE', 'Commit transaction'] as $boundary) {
            yield $boundary . ' finishes before expiry' => [$boundary, 29, OtpVerificationStatus::Verified];
            yield $boundary . ' finishes at expiry' => [$boundary, 30, OtpVerificationStatus::Invalid];
            yield $boundary . ' finishes after expiry' => [$boundary, 31, OtpVerificationStatus::Invalid];
        }
    }

    #[DataProvider('claimDelays')]
    public function testProofMustRemainUnexpiredWhenVerificationCompletes(
        string $boundary,
        int $delay,
        OtpVerificationStatus $status,
    ): void {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $store = new DatabaseOtpChallengeStore($database, $clock);
        $uuids = new UuidFactory();
        $challenge = new OtpChallenge(
            $uuids->generate(),
            $uuids->generate(),
            new OtpPurpose('authentication'),
            new OtpChannel('email'),
            'binding',
            $clock->now(),
            $clock->now()->modify('+30 seconds'),
        );
        $config = new OtpConfig();
        $verifier = str_repeat('a', 64);
        $store->issue($challenge, $verifier, $config);
        $driver = $database->getDriver(DatabaseInterface::WRITE);
        self::assertInstanceOf(LoggerAwareInterface::class, $driver);
        $logger = new class($clock, $boundary, $delay) extends AbstractLogger {
            public bool $advanced = false;

            public function __construct(
                private FrozenClock $clock,
                private string $boundary,
                private int $delay,
            ) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $sql = (string) $message;

                if (
                    !$this->advanced
                    && str_starts_with($sql, $this->boundary)
                    && ($this->boundary !== 'UPDATE' || str_contains($sql, 'auth_otp_challenges'))
                ) {
                    $this->advanced = true;
                    $this->clock->advance(sprintf('+%d seconds', $this->delay));
                }
            }
        };
        $driver->setLogger($logger);

        $verification = $store->verify($challenge->uuid, $challenge->binding, $verifier, $config);

        self::assertTrue($logger->advanced, 'The verification must cross the delayed database boundary.');
        self::assertSame($status, $verification->status);
        self::assertSame(
            OtpVerificationStatus::Invalid,
            $store->verify($challenge->uuid, $challenge->binding, $verifier, $config)->status,
        );
    }
}
