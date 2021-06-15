<?php

namespace Gvera\Helpers\security;

use Doctrine\ORM\EntityManager;
use Exception;
use Gvera\Helpers\locale\Locale;
use Gvera\Helpers\session\Session;
use Gvera\Models\User;
use Gvera\Services\UserService;

class SessionAuthenticationStrategy implements AuthenticationStrategyInterface
{
    private Session $session;
    private UserService $userService;
    private EntityManager $entityManager;
    private string $username;
    private string $password;

    public function __construct(
        Session $session,
        UserService $userService,
        EntityManager $entityManager,
        string $username = '',
        string $password = ''
    ) {
        $this->session = $session;
        $this->userService = $userService;
        $this->entityManager = $entityManager;
        $this->username = $username;
        $this->password = $password;
    }

    /**
     * @throws Exception
     */
    public function login()
    {
        $repository = $this->entityManager->getRepository(User::class);
        $user = $repository->findOneBy(['username' => $this->username]);

        if (!$user
            || $user->getUsername() != $this->username
            || !$user->getEnabled()
            || !$this->userService->validatePassword($this->password, $user->getPassword())) {
            throw new Exception('User is not allowed');
        }

        $this->session->set(
            'user',
            [
                'id' => $user->getId(),
                'username' => $this->username,
                'userEmail' => $user->getEmail(),
                'role' => $user->getRole()->getRolePriority()
            ]
        );
    }

    public function isLoggedIn(): bool
    {
        return $this->session->get('user') != null;
    }

    public function logout()
    {
        $this->session->destroy();
    }
}