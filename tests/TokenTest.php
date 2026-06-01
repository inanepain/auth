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

use Inane\Auth\TwoFactor\Token;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

/**
 * Tests for `Inane\Auth\TwoFactor\Token`.
 *
 * Verifies default token generation, length clamping, string casting, and
 * OTP URL formatting behaviour.
 */
final class TokenTest extends TestCase {
    /**
     * Ensures that accessing `$t->token` lazy‑generates a default Base32 token
     * with the expected default length of 32 characters.
     *
     * @return void
     */
    public function testGeneratesDefaultTokenOnAccess(): void {
        // Arrange: a token instance with no preset secret
        $t = new Token();

        // Act: trigger lazy generation via property hook
        $token = $t->token; // lazy-generate via property hook

        // Assert: token exists, is default length, and matches Base32 charset
        $this->assertNotEmpty($token, 'Token should be generated');
        $this->assertSame(32, \strlen($token), 'Default token length should be 32');
        $this->assertMatchesRegularExpression('/^[a-zA-Z2-7]+$/', $token, 'Token should be Base32 (A-Z2-7)');
    }

    /**
     * Confirms that the requested token length is clamped between 16 and 32
     * when generating a token explicitly via `generateToken()`.
     *
     * @return void
     * @throws RandomException
     */
    public function testLengthIsClampedBetween16And32(): void {
        // Arrange
        $t = new Token();

        // Act + Assert: below minimum -> clamped to 16
        $t->length = 4;
        $token16 = $t->generateToken();
        $this->assertSame(16, \strlen($token16));

        // Act + Assert: above maximum -> clamped to 32
        $t->length = 64;
        $token32 = $t->generateToken();
        $this->assertSame(32, \strlen($token32));
    }

    /**
     * Verifies that casting the token object to string returns the token
     * value and that the `token` property exposes the same value.
     *
     * @return void
     */
    public function testToStringReturnsTokenString(): void {
        $known = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
        $t = new Token($known, 'Alice');

        $this->assertSame($known, (string)$t);
        $this->assertSame($known, $t->token);
    }

    /**
     * Asserts that `getOTPUrl()` returns a properly formatted `otpauth://`
     * TOTP URI including label, secret, and issuer components (URL-encoded).
     *
     * @return void
     */
    public function testGetOtpUrlHasExpectedFormat(): void {
        $known = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
        $name = 'Alice Example';
        $issuer = 'Inane';
        $t = new Token($known, $name, $issuer);

        // Act
        $url = $t->getOTPUrl();

        // Assert: basic scheme + presence of required query parts
        $this->assertStringStartsWith('otpauth://totp/', $url);
        $this->assertStringContainsString('secret=' . rawurlencode($known), $url);
        $this->assertStringContainsString('issuer=' . rawurlencode($issuer), $url);
        // Label contains issuer:name (both urlencoded)
        $this->assertStringContainsString(rawurlencode($issuer) . ':' . rawurlencode($name), $url);
    }
}
