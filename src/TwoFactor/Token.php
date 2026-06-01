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

namespace Inane\Auth\TwoFactor;

use Inane\IdForge\Config\Characters;
use Inane\QR\QRObject;
use Random\RandomException;
use Stringable;

use function clamp;
use function random_int;
use function rawurlencode;
use function sprintf;
use function str_shuffle;
use function strlen;

use const true;

/**
 * Token
 *
 * Create a new TwoFactor Token (secret).
 *
 * @version 0.3.0
 */
class Token implements Stringable {
    #region Character Flags
    /**
     * Use alpha chars
     *
     * @var bool
     */
    public bool $useAlpha = true;

    /**
     * Use upper alpha chars
     *
     * @var bool
     */
    public bool $useAlphaUpper = true;

    /**
     * Use numeric chars
     *
     * @var bool
     */
    public bool $useNumeric = true;

    #endregion Character Flags

    #region Settings
    /**
     * Character Pool
     *
     * @var null|string
     */
    protected ?string $chars = null;

    /**
     * Token Length
     *
     * @var int
     */
    public int $length = 32 {
        get => $this->length;
        set => $this->length = clamp($value, 16, 32);
    }

    #endregion Settings

    /**
     * Token property accessor and mutator.
     *
     * When accessed, it returns the current token value. If the token is not set,
     * it generates a new token and assigns it before returning.
     * When mutated, it assigns the provided value to the token.
     *
     * @var string|null
     */
    protected(set) string $token {
        /**
         * @throws RandomException
         */
        get => $this->token ?? $this->token = $this->generateToken();
        set => $this->token = $value;
    }

    /**
     * Two-Factor Authentication Token
     *
     * @param string|null $token if null a new random token will be generated.
     * @param string      $name  token name (default: Unknown).
     */
    public function __construct(
        /**
         * Token
         */
        ?string                $token = null,
        /**
         * Token Name
         */
        private(set) string    $name = 'Unknown',
        /**
         * Token Account
         */
        public readonly string $issuer = 'Inane',
    ) {
        if ($token) $this->token = $token;
    }

    /**
     * Token String
     *
     * @return string Token
     */
    public function __toString(): string {
        return $this->token;
    }

    /**
     * Set Token
     *
     * @param string $token
     *
     * @return static
     */
    public function setToken(string $token): static {
        $this->token = $token;

        return $this;
    }

    /**
     * Set Token Name
     *
     * @param string $name
     *
     * @return static the $name
     */
    public function setName(string $name): static {
        $this->name = $name;

        return $this;
    }

    /**
     * Get chars to use it for Token
     *
     * @return string valid chars
     */
    protected function chars(): string {
        if ($this->chars === null) {
            $this->chars = '';

            $mask = 0;
            if ($this->useAlpha) $mask = Characters::useLower->addTo($mask);
            if ($this->useAlphaUpper) $mask = Characters::useUPPER->addTo($mask);
            if ($this->useNumeric) $mask = Characters::useNumeric->addTo($mask);

            $this->chars = Characters::base32($mask);
        }

        return $this->chars;
    }

    /**
     * Generates a random token based on the specified character set and length.
     *
     * @return string Generated token
     *
     * @throws RandomException If it was not possible to gather sufficient entropy for random_int()
     */
    public function generateToken(): string {
        $chars = $this->chars();
        $len = strlen($chars);
        $pw = '';

        for($i = 0; $i < $this->length; $i++) $pw .= $chars[random_int(0, $len - 1)];

        $this->token = str_shuffle($pw);

        return $this->token;
    }

    /**
     * Generates the OTP URL for the user.
     *
     * @return string OTP URL
     */
    public function getOTPUrl(): string {
        $username = $this->name; // or username
        $issuer = rawurlencode($this->issuer);
        $secret = $this->token; // uppercase A-Z2-7, no = padding

        $label = $issuer . ':' . rawurlencode($username);

        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s',
            $label,
            rawurlencode($secret),
            $issuer,
        );
    }

    /**
     * QRCode as a base64 image
     *
     * @return string base64 string of QRCode
     */
    public function getImageBase64(): string {
        return new QRObject($this->getOTPUrl())->getImageBase64();
    }
}
