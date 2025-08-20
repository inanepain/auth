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
 * @version $version
 */

declare(strict_types=1);

namespace Inane\Auth\Http;

use Stringable;

use function array_combine;
use function array_pop;
use function base64_decode;
use function explode;
use function is_null;
use function str_contains;
use const null;

/**
 * Basic Authorisation
 *
 * @package Inane\Auth
 *
 * @version 1.0.0
 */
class BasicAuth implements Stringable {
    /**
     * Username
     *
     * @var string
     */
    protected string $username;

    /**
     * Password
     *
     * @var string
     */
    protected string $password;

    public function __construct(?string $username = null, ?string $password = null) {
        if (!is_null($username)) $this->setUsername($username);
        if (!is_null($password)) $this->setPassword($password);
    }

    /**
     * Instantiate Basic from token
     *
     * @param string $token basic token
     *
     * @return static instance
     */
    public static function fromToken(string $token): static {
        return new static(...static::decodeBasicAuth($token));
    }

    /**
     * Decode a basic http auth token
     *
     * @param string $token encoded string
     *
     * @return null|array username, password array or null on failure
     */
    public static function decodeBasicAuth(string $token): ?array {
        $token = @array_pop(explode(' ', $token));
        $decoded = base64_decode($token);

        if (! str_contains($decoded, ':')) return null;

        return @array_combine(['username', 'password'], explode(':', $decoded, 2));
    }

    /**
     * Create a basic http auth token
     *
     * @param string $username username
     * @param string $password password
     *
     * @return string token
     */
    public static function encodeBasicAuth(string $username, string $password): string {
        return 'Basic ' . base64_encode("$username:$password");
    }

    /**
     * Returns token when used as string
     *
     * @return string token
     */
    public function __toString(): string {
        return $this->getToken() ?? '';
    }

    /**
     * Username
     *
     * @return string username
     */
    public function getUsername(): string {
        return $this->username;
    }

    /**
     * Set username
     *
     * @param string $username username
     *
     * @return \Inane\Auth\Http\BasicAuth this
     */
    public function setUsername(string $username): self {
        $this->username = $username;
        return $this;
    }

    /**
     * Password
     *
     * @return string password
     */
    public function getPassword(): string {
        return $this->password;
    }

    /**
     * Set password
     *
     * @param string $password password
     *
     * @return \Inane\Auth\Http\BasicAuth this
     */
    public function setPassword(string $password): self {
        $this->password = $password;
        return $this;
    }

    /**
     * Return basic auth token
     *
     * @return null|string token or null
     */
    public function getToken(): ?string {
        if (isset($this->username) && isset($this->password)) return static::encodeBasicAuth($this->username, $this->password);
        return null;
    }
}
