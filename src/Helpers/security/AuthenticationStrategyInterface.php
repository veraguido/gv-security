<?php

namespace Gvera\Helpers\security;

interface AuthenticationStrategyInterface
{
    public function login();
    public function isLoggedIn():bool;
    public function logout();
}
