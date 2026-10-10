<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\{DatabaseOtpChallengeStore, OtpChallengeManager, OtpChannel, OtpCodeGenerator, OtpCodeMac, OtpConfig, OtpPurpose, OtpVerificationStatus};
use Componenta\Auth\Otp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OtpCodeLengthCompatibilityTest extends TestCase
{
    /** @return iterable<string, array{int}> */
    public static function supportedCodeLengths(): iterable
    {
        foreach ([4, 5, 6, 7, 8] as $digits) {
            yield "digits-{$digits}" => [$digits];
        }
    }

    #[DataProvider('supportedCodeLengths')]
    public function testGeneratesExactlyTheConfiguredNumericLength(int $digits): void
    {
        $config = new OtpConfig(digits: $digits);
        $generator = new OtpCodeGenerator();

        for ($attempt = 0; $attempt < 20; ++$attempt) {
            $code = $generator->generate($config->digits);
            self::assertSame($digits, strlen($code));
            self::assertMatchesRegularExpression('/\A[0-9]{' . $digits . '}\z/D', $code);
        }
    }

    public function testRejectsOutOfRangeCodeLengths(): void
    {
        foreach ([0, 3, 9, 12] as $digits) {
            try {
                (new OtpCodeGenerator())->generate($digits);
                self::fail('OTP generator accepted invalid length ' . $digits);
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
            try {
                new OtpConfig(digits: $digits);
                self::fail('OTP configuration accepted invalid length ' . $digits);
            } catch (\InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    /** @return iterable<string, array{int}> */
    public static function shortCodeLengths(): iterable
    {
        yield 'legacy-four-digits' => [4];
        yield 'legacy-five-digits' => [5];
    }

    #[DataProvider('shortCodeLengths')]
    public function testFourAndFiveDigitChallengesVerifyOnceWithTheSharedManager(int $digits): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $manager = new OtpChallengeManager(
            new DatabaseOtpChallengeStore(SqliteDatabaseFixture::create(), $clock),
            new OtpCodeGenerator(),
            new OtpCodeMac(str_repeat('k', 32)),
            $clock,
            new OtpConfig(digits: $digits, resendCooldownSeconds: 0),
        );
        $purpose = new OtpPurpose('authentication');
        $binding = 'login-browser-binding';
        $issue = $manager->issue(
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789aaa'),
            Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
            $purpose, new OtpChannel('email'), $binding,
        );
        self::assertSame($digits, strlen($issue->code));
        self::assertSame(
            OtpVerificationStatus::Verified,
            $manager->verify($issue->challenge->uuid, $purpose, $binding, $issue->code)->status,
        );
        self::assertSame(
            OtpVerificationStatus::Invalid,
            $manager->verify($issue->challenge->uuid, $purpose, $binding, $issue->code)->status,
        );
    }

    public function testDefaultSecurityProfileRemainsSixDigits(): void
    {
        self::assertSame(6, (new OtpConfig())->digits);
    }
}
