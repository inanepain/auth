<?php
declare(strict_types=1);

namespace Inane\Auth\Tests;

use Inane\Auth\TwoFactor\OneTimePin;
use Inane\Auth\TwoFactor\Token;
use PHPUnit\Framework\TestCase;

final class OneTimePinTest extends TestCase
{
    public function testFromTokenKeyFactoryCreatesWithGivenKey(): void
    {
        $key = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
        $otp = OneTimePin::fromTokenKey($key, 'Unit Test');

        $this->assertInstanceOf(Token::class, $otp->getToken());
        $this->assertSame($key, $otp->getToken()->token);
    }

    public function testGetOtpReturnsSixDigits(): void
    {
        $otp = new OneTimePin(); // will auto-generate a Token

        $code = $otp->getOTP();

        $this->assertMatchesRegularExpression('/^\d{6}$/', $code, 'OTP should be six numeric digits');
    }

    public function testVerifyOtpPassesForCurrentCodeAndFailsForWrongOne(): void
    {
        $otp = new OneTimePin();

        $code = $otp->getOTP();

        // Should validate the current code
        $this->assertTrue($otp->verifyOTP($code));

        // An obviously incorrect code should fail
        $this->assertFalse($otp->verifyOTP('000000'));
    }

    public function testSetTokenWithNullGeneratesANewToken(): void
    {
        $otp = new OneTimePin(OneTimePin::fromTokenKey('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')->getToken());
        $first = $otp->getToken()->token;

        // Setting null should create a brand-new token internally
        $otp->setToken(null);
        $second = $otp->getToken()->token;

        $this->assertNotSame($first, $second);
        $this->assertMatchesRegularExpression('/^[a-zA-Z2-7]+$/', $second);
    }
}
