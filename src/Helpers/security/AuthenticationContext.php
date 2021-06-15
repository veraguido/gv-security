<?php

namespace Gvera\Helpers\security;

class AuthenticationContext
{
    private AuthenticationStrategyInterface $strategy;
    public function __construct(AuthenticationStrategyInterface $strategy)
    {
        $this->strategy = $strategy;
    }

    public function setStrategy(AuthenticationStrategyInterface $strategy)
    {
        $this->strategy = $strategy;
    }

    public function login()
    {
        $this->strategy->login();
    }

    public function isUserLoggedIn():bool
    {
        return $this->strategy->isLoggedIn();
    }

    public function logout()
    {
        $this->strategy->logout();
    }
}