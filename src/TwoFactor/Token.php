<?php

/**
 * Inane: Auth
 *
 * Authentication adapters for common use cases.
 *
 * $Id$
 * $Date$
 *
 * PHP version 8.4
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

use QRcode;
use Stringable;

use function is_bool;
use function is_numeric;
use function rand;
use function str_shuffle;
use function strlen;
use function substr;
use const false;
use const true;

/**
 * Token
 *
 * Create a new TwoFactor Token (secret).
 *
 * @version 0.2.0
 */
class Token implements Stringable {
    #region Constants
    /**
     * lower case alpha characters
     * 
     * @var string abcdefghijklmnopqrstuvwxyz
     */
    protected const string alpha = 'abcdefghijklmnopqrstuvwxyz';

    /**
     * UPPER CASE ALPHA CHARACTERS
     * 
     * @var string ABCDEFGHIJKLMNOPQRSTUVWXYZ
     */
    protected const string alphaUpper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * numeric characters
     * 
     * @var string 0123456789
     */
    protected const string numeric = '0123456789';

    /**
     * special characters
     * 
     * @var string .-+=_,!@$#*%<>[]{}
     */
    protected const string special = '.-+=_,!@$#*%<>[]{}';
    #endregion Constants

    #region Character Flags
    /**
     * Use alpha chars
     *
     * @var bool
     */
    protected(set) bool $useAlpha = true;

    /**
     * Use upper alpha chars
     *
     * @var bool
     */
    protected(set) bool $useAlphaUpper = true;

    /**
     * Use numeric chars
     *
     * @var bool
     */
    protected(set) bool $useNumeric = true;

    /**
     * Use special chars
     *
     * @var bool
     */
    protected(set) bool $useSpecial = false;
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
    protected int $length = 16;
    #endregion Settings

    /**
     * Token
     * 
     * @var string
     */
    private string $token {
        get => isset($this->token) ? $this->token : ($this->token = $this->generateToken());
        set => $this->token = $value;
    }

    /**
     * Two Factor Authentication Token
     *
     * @param string|null $token if null a new random token will be generated.
     * @param string $name token name (default: Unknown).
     */
    public function __construct(
        /**
         * Token
         */
        ?string $token = null,
        /**
         * Token Name
         */
        private(set) string $name = 'Unknown',
    ) {
        if ($token) $this->token = $token;
    }

    /**
     * Token String
     *
     * @return string Token
     */
    public function __toString(): string {
        return $this->getToken();
    }

    /**
     * Sets value for length
     *
     * @param int $length default: 16
     *
     * @return static
     */
    public function length(int $length = 16): static {
        if ($length > 7 && $length < 21) $this->length = $length;

        return $this;
    }

    /**
     * Set value for useAlpha
     *
     * @param bool $useAlpha default: true
     *
     * @return static
     */
    public function useAlpha(bool $useAlpha = true): static {
        $this->chars = null;
        $this->useAlpha = $useAlpha;

        return $this;
    }

    /**
     * Set value for useAlphaUpper
     *
     * @param bool $useAlphaUpper default: true
     *
     * @return static
     */
    public function useAlphaUpper(bool $useAlphaUpper = true): static {
        $this->chars = null;
        $this->useAlphaUpper = $useAlphaUpper;

        return $this;
    }

    /**
     * Set value for useNumeric
     *
     * @param bool $useNumeric default: true
     *
     * @return static
     */
    public function useNumeric(bool $useNumeric = true): static {
        $this->chars = null;
        $this->useNumeric = $useNumeric;

        return $this;
    }

    /**
     * Set value for useSpecial
     *
     * @param bool $useSpecial default: false
     *
     * @return static
     */
    public function useSpecial(bool $useSpecial = false): static {
        $this->chars = null;
        $this->useSpecial = $useSpecial;

        return $this;
    }

    /**
     * Get token
     *
     * Generating a new one if required.
     *
     * @return string token
     */
    public function getToken(): string {
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
     * Get Token Name
     *
     * @return string the $name
     */
    public function getName(): string {
        return $this->name;
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

            if ($this->useAlpha) $this->chars .= self::alpha;
            if ($this->useAlphaUpper) $this->chars .= self::alphaUpper;
            if ($this->useNumeric) $this->chars .= self::numeric;
            if ($this->useSpecial) $this->chars .= self::special;
        }
        return $this->chars;
    }

    /**
     * Generate Token
     *
     * @return string token
     */
    public function generateToken(): string {
        $chars = $this->chars();
        $len = strlen($chars);
        $pw = '';

        for ($i = 0; $i < $this->length; $i++) $pw .= substr($chars, rand(0, $len - 1), 1);

        $this->token = str_shuffle($pw);

        return $this->token;
    }

    /**
     * Token (secret) QRCode url
     *
     * @return string the QRCode url
     */
    protected function getQRCodeUrl(): string {
        $url = 'http://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Inane/' . $this->getName() . '?secret=' . $this->getToken();

        return $url;
    }

    /**
     * QRCode as base64 image
     *
     * @return string base64 string of QRCode
     */
    public function getImageBase64(): string {
	    $url = 'otpauth://totp/Inane/' . $this->getName() . '?secret=' . $this->getToken();
		return new \Inane\QR\QRObject($url)->getImageBase64();
    }
}
