# 

version: $Id$ ($Date$)

Authentication adapters for common use cases.

# Install

    $ composer require inanepain/auth

# Two-Factor Authentication

Generating and verifying tokens and pins.

## Generate Token

    $token = new \Inane\Authentication\TwoFactor\Token('Inane');
    echo "$token";

## Verify OTP

    $otp = new \Inane\Authentication\TwoFactor\OneTimePin($token);
    $valid = $otp->verifyOTP('612777');

## QRCode URL

    $imgUrl = $token->getQRCodeUrl();
    // OR
    $imgBase64 = $token->getImageBase64();
