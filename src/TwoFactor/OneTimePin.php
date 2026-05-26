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
 * @author Philip Michael Raab<philip@cathedral.co.za>
 * @package inanepain\ auth
 * @category auth
 *
 * @license UNLICENSE
 * @license https://unlicense.org/UNLICENSE UNLICENSE
 *
 * _version_ $version
 */

declare(strict_types=1);

namespace Inane\Auth\TwoFactor;

use function chr;
use function floor;
use function hash_hmac;
use function microtime;
use function ord;
use function pack;
use function preg_match;
use function str_pad;
use function strlen;
use function strtoupper;

use const false;
use const STR_PAD_LEFT;
use const true;

/**
 * OneTimePin
 *
 * Validate an otp pin against a Token (secret).
 *
 * @version 0.3.0
 */
class OneTimePin {
    /**
     * The number of seconds pin is valid on each side of expiry time.
     *
     * I.E.: OTP is valid for two times OTP_REGENERATION
     */
    private const int OTP_REGENERATION = 30;

    /**
     * Length of the pin
     */
    private const int OTP_LENGTH = 6;

    /**
     * Token
     */
    private Token $token;

    /**
     * Lookup needed for Base32 encoding
     *
     * @var array
     */
    private const array lut = [
        'A' => 0,
        'B' => 1,
        'C' => 2,
        'D' => 3,
        'E' => 4,
        'F' => 5,
        'G' => 6,
        'H' => 7,
        'I' => 8,
        'J' => 9,
        'K' => 10,
        'L' => 11,
        'M' => 12,
        'N' => 13,
        'O' => 14,
        'P' => 15,
        'Q' => 16,
        'R' => 17,
        'S' => 18,
        'T' => 19,
        'U' => 20,
        'V' => 21,
        'W' => 22,
        'X' => 23,
        'Y' => 24,
        'Z' => 25,
        '2' => 26,
        '3' => 27,
        '4' => 28,
        '5' => 29,
        '6' => 30,
        '7' => 31
    ];

    /**
     * OneTimePin constructor
     *
     * @param null|Token $token
     */
    public function __construct(?Token $token = null) {
        $this->setToken($token);
    }

    /**
     * Create using a token string
     *
     * @param string $key
     * @param string $name
     *
     * @return static
     */
    public static function fromTokenKey(string $key, string $name = 'Unknown'): static {
        $t = new Token($key, $name);
        return new static($t);
    }

    /**
     *  Get token
     *
     * @return Token $token
     */
    public function getToken(): Token {
        return $this->token;
    }

    /**
     * Set Token
     *  If none supplied a new Token is generated
     *
     * @param null|Token $token user token
     *
     * @return self
     */
    public function setToken(?Token $token = null): self {
        $this->token = $token ?? new Token();

        return $this;
    }

    /**
     * Get one time pin
     *
     * @since 0.3.0
     * @return string the current one time pin
     * @throws \Exception
     */
    public function getOTP(): string {
        return $this->oathOTP(self::base32Decode($this->getToken()->token), self::getTimestamp());
    }

    /**
     * Verifies user's otp against the current timestamp
     *
     * @param string $otp - User specified key
     *
     * @return boolean $otp validity
     * @throws \Exception
     */
    public function verifyOTP(string $otp): bool {
        return static::verifyKey($this->getToken()->token, $otp);
    }

    /**
     * Decodes a base32 string into a binary string.
     *
     * @param string $b32
     *
     * @return string
     * @throws \RuntimeException
     */
    private static function base32Decode(string $b32): string {
        $b32 = strtoupper($b32);
        if (! preg_match('/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]+$/', $b32)) throw new \RuntimeException('Invalid characters in the base32 string.');

        $l = strlen($b32);
        $n = 0;
        $j = 0;
        $binary = '';

        for ($i = 0; $i < $l; $i++) {
            $n <<= 5;                        // Move buffer left by 5 to make room
            $n += static::lut[$b32[$i]];     // Add value into buffer
            $j += 5;                         // Keep track of number of bits in buffer

            if ($j >= 8) {
                $j -= 8;
                $binary .= chr(($n & (0xFF << $j)) >> $j);
            }
        }

        return $binary;
    }

    /**
     * Returns the current timestamp divided by KEY_REGENERATION period
     *
     * @return float
     */
    private static function getTimestamp(): float {
        return floor(microtime(true) / static::OTP_REGENERATION);
    }

    /**
     * Takes secret key and timestamp and returns one time password
     *
     * @param string $key     - Secret key in binary form.
     * @param float  $counter - Timestamp as returned by getTimestamp.
     *
     * @return string OTP
     * @throws \RuntimeException
     */
    private static function oathOTP(string $key, float $counter): string {
        if (strlen($key) < 8) throw new \RuntimeException('Secret key is too short. Must be at least 16 base 32 characters');

        $bin_counter = pack('N*', 0) . pack('N*', $counter); // Counter must be 64-bit int
        $hash = hash_hmac('sha1', $bin_counter, $key, true);

        $t = static::oathTruncate($hash);
        return str_pad((string)$t, static::OTP_LENGTH, '0', STR_PAD_LEFT);
    }

    /**
     * Extracts the OTP from the SHA1 hash.
     *
     * @param string $hash
     *
     * @return int OTP
     */
    private static function oathTruncate(string $hash): int {
        $offset = ord($hash[19]) & 0xf;

        return (((ord($hash[$offset]) & 0x7f) << 24) | ((ord($hash[$offset + 1]) & 0xff) << 16) | ((ord($hash[$offset + 2]) & 0xff) << 8) | (ord($hash[$offset + 3]) & 0xff)) % (10 ** static::OTP_LENGTH);
    }

    /**
     * Verifies a user input key against the current timestamp
     *
     * @param string $b32seed      - seed
     * @param string $key          - user specified key
     * @param int    $window       - the number of keys check on either side of timestamp
     * @param bool   $useTimeStamp - use timestamp
     *
     * @return bool
     * @throws \Exception
     */
    private static function verifyKey(string $b32seed, string $key, int $window = 4, bool $useTimeStamp = true): bool {
        $timeStamp = static::getTimestamp();

        if ($useTimeStamp !== true) $timeStamp = (int) $useTimeStamp;

        $binarySeed = static::base32Decode($b32seed);

        for ($ts = $timeStamp - $window; $ts <= $timeStamp + $window; $ts++) if (static::oathOTP($binarySeed, $ts) === $key) return true;

        return false;
    }
}
