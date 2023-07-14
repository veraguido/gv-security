<?php

namespace Gvera\Services;

use DateTimeImmutable;
use Firebase\JWT\JWT;
use Gvera\Helpers\security\JWTTokenAuthenticationStrategy;
use Gvera\Models\User;

class JWTService
{
    public function createToken(User $user, int $expirationInSeconds = 900): string
    {
        $issuedAt   = new DateTimeImmutable();
        $expire     = $issuedAt->modify('+' . $expirationInSeconds . ' seconds')->getTimestamp();
        $username   = $user->getUsername();

        $data = [
            'iat'  => $issuedAt->getTimestamp(),         // Issued at: time when the token was generated
            'nbf'  => $issuedAt->getTimestamp(),         // Not before
            'exp'  => $expire,                           // Expire
            'username' => $username,                     // User name
        ];

        return JWT::encode($data, JWTTokenAuthenticationStrategy::SECRET_KEY, 'HS256');
    }
}
