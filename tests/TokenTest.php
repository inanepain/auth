<?php
declare(strict_types=1);

namespace Inane\Auth\Tests;

use Inane\Auth\TwoFactor\Token;
use PHPUnit\Framework\TestCase;

final class TokenTest extends TestCase
{
    public function testGeneratesDefaultTokenOnAccess(): void
    {
        $t = new Token();

        $token = $t->token; // lazy-generate via property hook

        $this->assertNotEmpty($token, 'Token should be generated');
        $this->assertSame(32, \strlen($token), 'Default token length should be 32');
        $this->assertMatchesRegularExpression('/^[a-zA-Z2-7]+$/', $token, 'Token should be Base32 (A-Z2-7)');
    }

    public function testLengthIsClampedBetween16And32(): void
    {
        $t = new Token();

        // Below minimum -> clamp to 16
        $t->length = 4;
        $token16 = $t->generateToken();
        $this->assertSame(16, \strlen($token16));

        // Above maximum -> clamp to 32
        $t->length = 64;
        $token32 = $t->generateToken();
        $this->assertSame(32, \strlen($token32));
    }

    public function testToStringReturnsTokenString(): void
    {
        $known = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
        $t = new Token($known, 'Alice');

        $this->assertSame($known, (string)$t);
        $this->assertSame($known, $t->token);
    }

    public function testGetOtpUrlHasExpectedFormat(): void
    {
        $known = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
        $name = 'Alice Example';
        $issuer = 'Inane';
        $t = new Token($known, $name, $issuer);

        $url = $t->getOTPUrl();

        $this->assertStringStartsWith('otpauth://totp/', $url);
        $this->assertStringContainsString('secret=' . rawurlencode($known), $url);
        $this->assertStringContainsString('issuer=' . rawurlencode($issuer), $url);
        // Label contains issuer:name (both urlencoded)
        $this->assertStringContainsString(rawurlencode($issuer) . ':' . rawurlencode($name), $url);
    }
}
