<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\{OtpCodeGenerator, OtpConfig};
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

    public function testDefaultSecurityProfileRemainsSixDigits(): void
    {
        self::assertSame(6, (new OtpConfig())->digits);
    }
}
