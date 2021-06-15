<?php

namespace Tests;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityRepository;
use Gvera\Cache\Cache;
use Gvera\Commands\LoginCommand;
use Gvera\Helpers\config\Config;
use Gvera\Helpers\events\EventDispatcher;
use Gvera\Helpers\session\Session;
use Gvera\Models\User;
use Gvera\Models\UserRole;
use Gvera\Services\UserService;
use PHPUnit\Framework\TestCase;

class CommandsTest extends TestCase
{
    /**
     * @test
     * @throws \Exception
     */
    public function testLoginCommand()
    {

        $role = new UserRole();
        $role->setName('asd');
        $role->setRolePriority(3);

        $user = new User();
        $user->setId(2);
        $user->setRole($role);
        $user->setEmail("asd@aasd.com");
        $user->setEnabled(true);
        $user->setUsername("admin");
        $user->setPassword(password_hash("admin", PASSWORD_BCRYPT));

        $repo = $this->createMock(EntityRepository::class);
        $repo->expects($this->any())
            ->method('findOneBy')
            ->willReturn($user);

        $gvEntityManager = $this->createMock(EntityManager::class);
        $gvEntityManager->expects($this->any())
            ->method('getRepository')
            ->willReturn($repo);

        $session = new Session();
        $userService = new UserService($gvEntityManager, $session);
        $command = new LoginCommand($userService, new EventDispatcher());
        $command->setPassword('admin');
        $command->setUsername($user->getUsername());
        $command->execute();

        $this->assertTrue($userService->isUserLoggedIn());

    }

}