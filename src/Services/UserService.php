<?php namespace Gvera\Services;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\OptimisticLockException;
use Doctrine\ORM\ORMException;
use Exception;
use Gvera\Commands\CreateNewUserCommand;
use Gvera\Exceptions\BadRequestException;
use Gvera\Exceptions\NotFoundException;
use Gvera\Helpers\http\HttpRequest;
use Gvera\Helpers\locale\Locale;
use Gvera\Helpers\security\AuthenticationContext;
use Gvera\Helpers\security\SessionAuthenticationStrategy;
use Gvera\Helpers\session\Session;
use Gvera\Helpers\validation\EmailValidationStrategy;
use Gvera\Helpers\validation\ValidationService;
use Gvera\Models\User;
use Gvera\Models\UserRole;
use Gvera\Models\UserRoleAction;
use phpDocumentor\Reflection\Types\Boolean;

/**
 * Service Class Doc Comment
 *
 * @category Class
 * @package  src/services
 * @author    Guido Vera
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     http://www.github.com/veraguido/gv
 *
 */
class UserService
{
    const MODERATOR_ROLE_PRIORITY = 5;

    public EntityManager $entityManager;
    public Session $session;

    public function __construct(EntityManager $entityManager, Session $session)
    {
        $this->entityManager = $entityManager;
        $this->session = $session;
    }

    /**
     * @param $plainPassword
     * @return string
     */
    public function generatePassword($plainPassword): string
    {
        return password_hash($plainPassword, PASSWORD_BCRYPT);
    }

    /**
     * @param $plainPassword
     * @param $hash
     * @return bool
     */
    public function validatePassword($plainPassword, $hash): bool
    {
        return password_verify($plainPassword, $hash);
    }

    /**
     * @param $username
     * @param $password
     * @throws Exception
     */
    public function login($username, $password)
    {
        $strategy = new SessionAuthenticationStrategy(
            $this->session,
            $this,
            $this->entityManager,
            $username,
            $password
        );
        $context = new AuthenticationContext($strategy);
        $context->login();
    }

    public function logout()
    {
        $strategy = new SessionAuthenticationStrategy(
            $this->session,
            $this,
            $this->entityManager
        );
        $context = new AuthenticationContext($strategy);
        $context->logout();
    }

    public function isUserLoggedIn(): bool
    {
        $strategy = new SessionAuthenticationStrategy(
            $this->session,
            $this,
            $this->entityManager
        );
        $context = new AuthenticationContext($strategy);
        return $context->isUserLoggedIn();
    }

    /**
     * @return int
     */
    public function getSessionUserRole()
    {
        return $this->session->get('user') != null ? $this->session->get('user')['role'] : false;
    }

    /**
     * @param User|null $user
     * @param string $userRoleActionName
     * @return bool
     */
    public function userCan(?User $user, string $userRoleActionName):bool
    {
        if (null === $user) {
            return false;
        }

        $action = $this->entityManager->getRepository(UserRoleAction::class)
            ->findOneBy(['name' => $userRoleActionName]);


        if (null == $action) {
            return false;
        }

        return $user->getRole()->getUserRoleActions()->contains($action);
    }

    /**
     * @param HttpRequest $httpRequest
     * @param CreateNewUserCommand $command
     * @param UserRole $role
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function createFromRequest(HttpRequest $httpRequest, CreateNewUserCommand $command, UserRole $role)
    {
        $command->setEmail($httpRequest->getParameter('email'));
        $command->setName($httpRequest->getParameter('username'));
        $hashedPassword = $this->generatePassword($httpRequest->getParameter('password'));
        $command->setPassword($hashedPassword);
        $command->setRole($role);
        $command->execute();

        $this->entityManager->flush();
    }

    /**
     * @param HttpRequest $request
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function updateFromRequest(HttpRequest $request)
    {
        $userRepository = $this->entityManager->getRepository(User::class);
        $id = intval($request->getParameter('user_id'));
        $newPassword = $this->generatePassword($request->getParameter('password'));
        $user = $userRepository->find($id);
        $user->setPassword($newPassword);

        $this->entityManager->merge($user);
        $this->entityManager->flush();
    }

    /**
     * @param HttpRequest $request
     * @throws ORMException
     * @throws OptimisticLockException
     */
    public function toggleUser(HttpRequest $request)
    {
        $userRepository = $this->entityManager->getRepository(User::class);

        $id = intval($request->getParameter('user_id'));
        $user = $userRepository->find($id);
        $user->setEnabled(!$user->getEnabled());
        $this->entityManager->merge($user);
        $this->entityManager->flush();
    }
}
