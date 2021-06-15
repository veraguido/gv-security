<?php

namespace Gvera\Helpers\security;

use DateTime;
use Doctrine\ORM\EntityManager;
use Exception;
use Firebase\JWT\JWT;
use Gvera\Exceptions\NotAllowedException;
use Gvera\Exceptions\TokenExpiredException;
use Gvera\Helpers\entities\GvEntityManager;
use Gvera\Models\User;

class JWTTokenAuthenticationStrategy implements AuthenticationStrategyInterface
{
    private string $tokenValue;
    const SECRET_KEY = 'pqjwpoj1231jpojdqw_12e12o-0qw!_%gvlllpj34';
    private EntityManager $entityManager;

    public function __construct(string $tokenValue, EntityManager $entityManager)
    {
        $this->tokenValue = $tokenValue;
        $this->entityManager = $entityManager;
    }

    public function login()
    {
        // nothing to do in this method for this strategy
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function isLoggedIn(): bool
    {
        $decoded = JWT::decode($this->tokenValue, self::SECRET_KEY, ['HS256']);
        if (!isset($decoded->username)) {
            throw new NotAllowedException('User is not allowed');
        }

        $user = $this->entityManager->
        getRepository(User::class)
            ->findOneBy(['username' => $decoded->username]);

        return null !== $user;
    }

    public function logout()
    {
        // nothing to do in this method for this strategy
    }
}