<?php

namespace Tests;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityRepository;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Gvera\Exceptions\NotAllowedException;
use Gvera\Exceptions\TokenExpiredException;
use Gvera\Helpers\entities\GvEntityManager;
use Gvera\Helpers\security\AuthenticationContext;
use Gvera\Helpers\security\BasicAuthenticationStrategy;
use Gvera\Helpers\security\JWTTokenAuthenticationStrategy;
use Gvera\Helpers\security\SessionAuthenticationStrategy;
use Gvera\Helpers\session\Session;
use Gvera\Models\BasicAuthenticationDetails;
use Gvera\Models\User;
use Gvera\Models\UserRole;
use Gvera\Services\JWTService;
use Gvera\Services\UserService;

class AuthenticationStrategiesTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     */
    public function testBasicAuth()
    {

        $user = new User();
        $user->setEmail("asd@aasd.com");
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

        $userService = new UserService($gvEntityManager, new Session());

        $strategy = new BasicAuthenticationStrategy(
            $gvEntityManager,
            $userService,
            new BasicAuthenticationDetails('admin', 'admin')
        );

        $context = new AuthenticationContext($strategy);
        $this->assertTrue($context->isUserLoggedIn());

        $falsyStrategy = new BasicAuthenticationStrategy(
            $gvEntityManager,
            $userService,
            null
        );

        $context = new AuthenticationContext($falsyStrategy);
        $this->assertFalse($context->isUserLoggedIn());

        $falsyRepo = $this->createMock(EntityRepository::class);
        $falsyRepo->expects($this->any())
            ->method('findOneBy')
            ->willReturn(null);

        $falsyEntityManager = $this->createMock(EntityManager::class);
        $falsyEntityManager->expects($this->any())
            ->method('getRepository')
            ->willReturn($falsyRepo);

        $secondFalsyStrategy = new BasicAuthenticationStrategy(
            $falsyEntityManager,
            $userService,
            new BasicAuthenticationDetails('asd', 'admin')
        );
        $context = new AuthenticationContext($secondFalsyStrategy);
        $context->setStrategy($secondFalsyStrategy);
        $context->logout();
        $context->login();
        $this->assertFalse($context->isUserLoggedIn());
    }

    /**
     * @test
     */
    public function testJWTStrategy()
    {
        $user = new User();
        $user->setEmail("asd@aasd.com");
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

        $tokenService = new JWTService();
        $token = $tokenService->createToken($user);
        $strategy = new JWTTokenAuthenticationStrategy($token, $gvEntityManager);

        $context = new AuthenticationContext($strategy);
        $context->login();
        $context->logout();
        $this->assertTrue($context->isUserLoggedIn());

        $issuedAt   = new \DateTimeImmutable();
        $expire     = $issuedAt->modify('+900 seconds')->getTimestamp();

        $data = [
            'iat'  => $issuedAt->getTimestamp(),         // Issued at: time when the token was generated
            'nbf'  => $issuedAt->getTimestamp(),         // Not before
            'exp'  => $expire,                           // Expire
        ];


        $newToken = JWT::encode($data, JWTTokenAuthenticationStrategy::SECRET_KEY, 'HS256');
        $strategy = new JWTTokenAuthenticationStrategy($newToken, $gvEntityManager);
        $context = new AuthenticationContext($strategy);
        $this->expectException(NotAllowedException::class);
        $context->isUserLoggedIn();

        $newToken = $tokenService->createToken($user, 1);
        $strategy = new JWTTokenAuthenticationStrategy($newToken, $gvEntityManager);
        $context = new AuthenticationContext($strategy);
        sleep(2);
        $this->expectException(ExpiredException::class);
        $context->isUserLoggedIn();
    }

    /**
     * @test
     */
    public function testSessionStrategy()
    {

        $role = new UserRole();
        $role->setName('asd');
        $role->setRolePriority(3);


        $user = $this->createMock(User::class);
        $user->expects($this->any())->method('getId')->willReturn(2);
        $user->expects($this->any())->method('getRole')->willReturn($role);
        $user->expects($this->any())->method('getEmail')->willReturn("asd@aasd.com");
        $user->expects($this->any())->method('getEnabled')->willReturn(true);
        $user->expects($this->any())->method('getUsername')->willReturn('admin');
        $user->expects($this->any())->method('getPassword')->willReturn(password_hash("admin", PASSWORD_BCRYPT));

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

        $strategy = new SessionAuthenticationStrategy($session,$userService, $gvEntityManager, 'admin', 'admin');
        $context = new AuthenticationContext($strategy);
        $context->login();
        $this->assertNotEmpty($session->get('user'));
        $this->assertTrue($context->isUserLoggedIn());
        $context->logout();
        $this->assertFalse($session->get('user'));

        $newStrategy = new SessionAuthenticationStrategy($session,$userService, $gvEntityManager, 'asd', 'admin');
        $context = new AuthenticationContext($newStrategy);
        $this->expectException(\Exception::class);
        $context->login();
    }
}