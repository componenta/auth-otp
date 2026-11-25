<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\DatabaseOtpChallengeStore;
use Componenta\Auth\Otp\OtpChallenge;
use Componenta\Auth\Otp\OtpChallengeManager;
use Componenta\Auth\Otp\OtpChannel;
use Componenta\Auth\Otp\OtpCodeGenerator;
use Componenta\Auth\Otp\OtpCodeMac;
use Componenta\Auth\Otp\OtpConfig;
use Componenta\Auth\Otp\OtpDeliveryInterface;
use Componenta\Auth\Otp\OtpIdentityProviderInterface;
use Componenta\Auth\Otp\OtpIssueThrottledException;
use Componenta\Auth\Otp\OtpPurpose;
use Componenta\Auth\Otp\OtpRequest;
use Componenta\Auth\Otp\OtpRequestProcessor;
use Componenta\Auth\Otp\OtpVerificationStatus;
use Componenta\Auth\Otp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use PHPUnit\Framework\TestCase;

final class OtpRequestProcessorTest extends TestCase
{
    public function testDeliveryFailureRevokesProofAndRetainsIssuanceBudget(): void
    {
        $manager = $this->manager();
        $uuids = new UuidFactory();
        $subject = $uuids->generate();
        $request = new OtpRequest($uuids->generate(), 'user@example.test', new OtpPurpose('authentication'), new OtpChannel('email'), 'browser');
        $failure = new \RuntimeException('delivery failed');
        $delivery = new RecordingOtpDelivery($failure);

        try {
            (new OtpRequestProcessor($this->identities($subject), $manager, $delivery))->process($request);
            self::fail('The delivery failure must propagate.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }

        self::assertNotNull($delivery->code);
        self::assertSame(OtpVerificationStatus::Invalid, $manager->verify(
            $request->challengeId,
            $request->purpose,
            $request->binding,
            $delivery->code,
        )->status);

        $this->expectException(OtpIssueThrottledException::class);
        $manager->issue($uuids->generate(), $subject, $request->purpose, $request->channel, 'another-browser');
    }

    public function testSuccessfulDeliveryLeavesTheProofUsableOnce(): void
    {
        $manager = $this->manager();
        $uuids = new UuidFactory();
        $subject = $uuids->generate();
        $request = new OtpRequest($uuids->generate(), 'user@example.test', new OtpPurpose('authentication'), new OtpChannel('email'), 'browser');
        $delivery = new RecordingOtpDelivery();

        (new OtpRequestProcessor($this->identities($subject), $manager, $delivery))->process($request);

        self::assertNotNull($delivery->code);
        $first = $manager->verify($request->challengeId, $request->purpose, $request->binding, $delivery->code);
        self::assertSame(OtpVerificationStatus::Verified, $first->status);
        self::assertTrue($subject->equals($first->subjectId));
        self::assertSame(OtpVerificationStatus::Invalid, $manager->verify(
            $request->challengeId,
            $request->purpose,
            $request->binding,
            $delivery->code,
        )->status);
    }

    private function manager(): OtpChallengeManager
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');

        return new OtpChallengeManager(
            new DatabaseOtpChallengeStore(SqliteDatabaseFixture::create(), $clock),
            new OtpCodeGenerator(),
            new OtpCodeMac(str_repeat('k', 32)),
            $clock,
            new OtpConfig(resendCooldownSeconds: 0, maxIssuesPerWindow: 1),
        );
    }

    private function identities(UuidInterface $subject): OtpIdentityProviderInterface
    {
        $identity = new readonly class($subject) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $provider = $this->createStub(OtpIdentityProviderInterface::class);
        $provider->method('findByIdentity')->willReturn($identity);

        return $provider;
    }
}

final class RecordingOtpDelivery implements OtpDeliveryInterface
{
    public ?string $code = null;

    public function __construct(private ?\Throwable $failure = null) {}

    public function send(string $destination, OtpChallenge $challenge, string $code): void
    {
        $this->code = $code;

        if ($this->failure !== null) {
            throw $this->failure;
        }
    }
}
