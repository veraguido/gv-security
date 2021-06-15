<?php

namespace Gvera\Helpers\security;

use Doctrine\ORM\EntityManager;
use Gvera\Models\BasicAuthenticationDetails;
use Gvera\Models\User;
use Gvera\Services\UserService;

class BasicAuthenticationStrategy implements AuthenticationStrategyInterface
{
    private ?BasicAuthenticationDetails $details;
    private EntityManager $entityManager;
    private UserService $userService;

    public function __construct(
        EntityManager $entityManager,
        UserService $userService,
        ?BasicAuthenticationDetails $details
    ) {
        $this->entityManager = $entityManager;
        $this->userService = $userService;
        $this->details = $details;
    }

    public function login()
    {
        //nothing to do in this method on this strategy
    }

    public function isLoggedIn(): bool
    {

        if (!isset($this->details)) {
            return false;
        }

        $user = $this->entityManager->getRepository(User::class)
            ->findOneBy(['username' => $this->details->getUsername()]);

        if (null === $user) {
            return false;
        }

        return $this->userService->validatePassword($this->details->getPassword(), $user->getPassword());
    }

    public function logout()
    {
        //nothing to do here in this strategy
    }
}