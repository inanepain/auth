# Inanepain: Authentication

> $Id$ ($Date$)

Stuff to help with or add to authentication.

## Two Factor Authentication

Generating and verifying tokens and pins.

### Generate Token

```php
$token = new \Inane\Authentication\TwoFactor\Token('Inane');
echo "$token";
```

### Verify OTP

```php
$otp = new \Inane\Authentication\TwoFactor\OneTimePin($token);
$valid = $otp->verifyOTP('612777');
```

### QRCode URL

```php
$imgUrl = $token->getQRCodeUrl();
// OR
$imgBase64 = $token->getImageBase64();
```
