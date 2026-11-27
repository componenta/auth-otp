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
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerAwareInterface;

final class BudgetLockRetentionTest extends TestCase
{
    private DatabaseInterface $database;
    private DatabaseOtpChallengeStore $store;
    private FrozenClock $clock;
    private OtpConfig $config;
    private UuidInterface $subject;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $this->database = SqliteDatabaseFixture::create();
        $this->clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $this->store = new DatabaseOtpChallengeStore($this->database, $this->clock);
        $this->config = new OtpConfig(resendCooldownSeconds: 0, aggregateFailureLimit: 2);
        $this->subject = (new UuidFactory())->generate();
    }

    public function testSuccessfulProofResetsFailuresForAnotherValidChallenge(): void
    {
        $first = $this->challenge('browser-a');
        $second = $this->challenge('browser-b');
        $correct = str_repeat('a', 64);
        $incorrect = str_repeat('b', 64);
        $this->store->issue($first, $correct, $this->config);
        $this->store->issue($second, $correct, $this->config);

        self::assertSame(OtpVerificationStatus::Invalid, $this->store->verify(
            $first->uuid, $first->binding, $incorrect, $this->config,
        )->status);
        self::assertSame(OtpVerificationStatus::Verified, $this->store->verify(
            $first->uuid, $first->binding, $correct, $this->config,
        )->status);
        self::assertSame(OtpVerificationStatus::Invalid, $this->store->verify(
            $second->uuid, $second->binding, $incorrect, $this->config,
        )->status, 'A successful proof resets the subject failure budget.');
        self::assertSame(OtpVerificationStatus::Verified, $this->store->verify(
            $second->uuid, $second->binding, $correct, $this->config,
        )->status);
    }

    public static function waitingOperations(): iterable
    {
        yield 'verification waits for another successful proof' => [false];
        yield 'issuance waits for another successful proof' => [true];
    }

    #[DataProvider('waitingOperations')]
    public function testSuccessfulProofDoesNotRemoveAnotherOperationsMutex(bool $issuing): void
    {
        $first = $this->challenge('browser-a');
        $second = $this->challenge('browser-b');
        $verifier = str_repeat('a', 64);
        $this->store->issue($first, $verifier, $this->config);

        if (!$issuing) {
            $this->store->issue($second, $verifier, $this->config);
        }

        $driver = $this->database->getDriver(DatabaseInterface::WRITE);
        self::assertInstanceOf(LoggerAwareInterface::class, $driver);
        // Model the Read Committed schedule after the no-op INSERT and before
        // the mutex UPDATE: another valid proof commits a budget reset. The
        // public driver logger gives a deterministic boundary without sleeps;
        // this checks the resulting state, not native PostgreSQL contention.
        $logger = new class(function () use ($first, $verifier): void {
            self::assertSame(OtpVerificationStatus::Verified, $this->store->verify(
                $first->uuid, $first->binding, $verifier, $this->config,
            )->status);
        }) extends AbstractLogger {
            public bool $triggered = false;

            public function __construct(private readonly \Closure $verifyOtherChallenge) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $sql = (string) $message;

                if (
                    !$this->triggered
                    && str_starts_with($sql, 'INSERT')
                    && str_contains($sql, 'auth_otp_failure_budgets')
                    && str_contains($sql, 'DO NOTHING')
                ) {
                    $this->triggered = true;
                    ($this->verifyOtherChallenge)();
                }
            }
        };
        $driver->setLogger($logger);

        if ($issuing) {
            $this->store->issue($second, $verifier, $this->config);
        }

        self::assertSame(OtpVerificationStatus::Verified, $this->store->verify(
            $second->uuid, $second->binding, $verifier, $this->config,
        )->status);
        self::assertTrue($logger->triggered, 'The test must cross the mutex acquisition boundary.');

        foreach ([$first, $second] as $challenge) {
            self::assertSame(OtpVerificationStatus::Invalid, $this->store->verify(
                $challenge->uuid, $challenge->binding, $verifier, $this->config,
            )->status, 'Both valid proofs remain single-use.');
        }
    }

    private function challenge(string $binding): OtpChallenge
    {
        return new OtpChallenge(
            (new UuidFactory())->generate(),
            $this->subject,
            new OtpPurpose('authentication'),
            new OtpChannel('email'),
            $binding,
            $this->clock->now(),
            $this->clock->now()->modify('+300 seconds'),
        );
    }
}
