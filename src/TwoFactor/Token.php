<?php

declare(strict_types=1);

namespace Inane\Authentication\TwoFactor;

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
 * @author philip
 * @version 0.2.0
 */
class Token implements Stringable {
    /**
     * @var string
     */
    protected static string $alpha = 'abcdefghijklmnopqrstuvwxyz';

    /**
     * @var string
     */
    protected static string $alphaUpper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /**
     * @var string
     */
    protected static string $numeric = '0123456789';

    /**
     * @var string
     */
    protected static string $special = '.-+=_,!@$#*%<>[]{}';

    /**
     * Token
     */
    private string $token;

    /**
     * Char Pool
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

    /**
     * Use alpha chars
     *
     * @var bool
     */
    protected bool $useAlpha = true;

    /**
     * Use upper alpha chars
     *
     * @var bool
     */
    protected bool $useAlphaUpper = true;

    /**
     * Use numeric chars
     *
     * @var bool
     */
    protected bool $useNumeric = true;

    /**
     * Use special chars
     *
     * @var bool
     */
    protected bool $useSpecial = false;

    /**
     * Two Factor Authentication Token
     *
     * @param string|null $token
     * @param string $name
     */
    public function __construct(
        /**
         * Token Name
         */
        private string $name = 'Unknown',
        /**
         * Token
         */
        ?string $token = null,
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
     * gets/sets value for length
     *
     * @param null|int $length
     *
     * @return int the $length
     */
    public function length(?int $length = null): int {
        if (is_numeric($length) && $length > 7 && $length < 21) $this->length = $length;

        return $this->length;
    }

    /**
     * get/set value for useAlpha
     *
     * @param null|bool $useAlpha
     *
     * @return boolean
     */
    public function useAlpha(?bool $useAlpha = null): bool {
        if (is_bool($useAlpha) && $useAlpha != $this->useAlpha) {
            $this->chars = null;
            $this->useAlpha = $useAlpha;
        }

        return $this->useAlpha;
    }

    /**
     * get/set value for useAlphaUpper
     *
     * @param null|bool $useAlphaUpper
     *
     * @return boolean
     */
    public function useAlphaUpper(?bool $useAlphaUpper = null): bool {
        if (is_bool($useAlphaUpper) && $useAlphaUpper != $this->useAlphaUpper) {
            $this->chars = null;
            $this->useAlphaUpper = $useAlphaUpper;
        }

        return $this->useAlphaUpper;
    }

    /**
     * get/set value for useNumeric
     *
     * @param null|bool $useNumeric
     *
     * @return boolean
     */
    public function useNumeric(?bool $useNumeric = null): bool {
        if (is_bool($useNumeric) && $useNumeric != $this->useNumeric) {
            $this->chars = null;
            $this->useNumeric = $useNumeric;
        }

        return $this->useNumeric;
    }

    /**
     * get/set value for useSpecial
     *
     * @param null|bool $useSpecial
     *
     * @return boolean
     */
    public function useSpecial(?bool $useSpecial = null): bool {
        if (is_bool($useSpecial) && $useSpecial != $this->useSpecial) {
            $this->chars = null;
            $this->useSpecial = $useSpecial;
        }

        return $this->useSpecial;
    }

    /**
     * Get token
     *
     * Generating a new one if required.
     *
     * @return string token
     */
    public function getToken(): string {
        if (!isset($this->token)) $this->token = $this->generateToken();

        return $this->token;
    }

    public function setToken(string $token): self {
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
     * Get chars to use for Token
     *
     * @return string valid chars
     */
    protected function chars(): string {
        if (is_null($this->chars)) {
            $this->chars = '';

            if ($this->useAlpha) $this->chars .= static::$alpha;
            if ($this->useAlphaUpper) $this->chars .= static::$alphaUpper;
            if ($this->useNumeric) $this->chars .= static::$numeric;
            if ($this->useSpecial) $this->chars .= static::$special;
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
    public function getQRCodeUrl(): string {
        $url = 'http://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Inane/' . $this->getName() . '?secret=' . $this->getToken();

        return $url;
    }

    /**
     * QRCode as base64 image
     *
     * @return string base64 string of QRCode
     */
    public function getImageBase64(): string {
        $url = $this->getQRCodeUrl();
        $data = file_get_contents($url);
        $base64 = 'data:image/png;base64,' . base64_encode($data);

        return $base64;
    }
}
