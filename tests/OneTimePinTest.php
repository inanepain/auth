<?php

/**
 * Inane: Auth
 *
 * Authentication adapters for common use cases.
 *
 * $Id$
 * $Date$
 *
 * PHP version 8.5
 *
 * @author   Philip Michael Raab<philip@cathedral.co.za>
 * @package  inanepain\auth
 * @category auth
 *
 * @license  UNLICENSE
 * @license  https://unlicense.org/UNLICENSE UNLICENSE
 *
 * _version_ $version
 */

declare(strict_types = 1);

namespace Inane\Auth\Tests;

use Exception;
use Inane\Auth\TwoFactor\{
    OneTimePin,
    Token};
use PHPUnit\Framework\TestCase;

/**
 * Test suite for `Inane\Auth\TwoFactor\OneTimePin`.
 *
 * Verifies basic factory creation, OTP generation format, verification logic,
 * and token (re)assignment behaviours.
 */
final class OneTimePinTest extends TestCase {
    /**
     * Ensures `OneTimePin::fromTokenKey` creates an instance whose underlying
     * `Token` contains the provided key.
     *
     * @return void
     */
    public function testFromTokenKeyFactoryCreatesWithGivenKey(): void {
        $key = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
        // Create OTP using the factory method with a deterministic key
        $otp = OneTimePin::fromTokenKey($key, 'Unit Test');

        $this->assertInstanceOf(Token::class, $otp->getToken());
        $this->assertSame($key, $otp->getToken()->token);
    }

    /**
     * Confirms that generated OTPs are six numeric digits as per spec.
     *
     * @return void
     * @throws Exception
     */
    public function testGetOtpReturnsSixDigits(): void {
        // Instantiate without arguments to auto-generate a `Token`
        $otp = new OneTimePin();

        $code = $otp->getOTP();

        $this->assertMatchesRegularExpression('/^\d{6}$/', $code, 'OTP should be six numeric digits');
    }

    /**
     * Verifies that the current OTP validates successfully and that an
     * obviously incorrect OTP is rejected.
     *
     * @return void
     * @throws Exception
     */
    public function testVerifyOtpPassesForCurrentCodeAndFailsForWrongOne(): void {
        $otp = new OneTimePin();

        $code = $otp->getOTP();

        // Should validate the current code
        $this->assertTrue($otp->verifyOTP($code));

        // An obviously incorrect code should fail
        $this->assertFalse($otp->verifyOTP('000000'));
    }

    /**
     * When setting the token to `null`, a brand-new token must be generated
     * internally, resulting in a different token string.
     *
     * @return void
     */
    public function testSetTokenWithNullGeneratesANewToken(): void {
        $otp = new OneTimePin(
            OneTimePin::fromTokenKey('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')
                ->getToken(),
        );
        $first = $otp->getToken()->token;

        // Setting null should create a brand-new token internally
        $otp->setToken(null);
        $second = $otp->getToken()->token;

        $this->assertNotSame($first, $second);
        $this->assertMatchesRegularExpression('/^[a-zA-Z2-7]+$/', $second);
    }
}
