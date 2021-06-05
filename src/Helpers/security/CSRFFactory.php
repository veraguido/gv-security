<?php

namespace Gvera\Helpers\security;

use Exception;

class CSRFFactory
{
    /**
     * @return CSRFToken
     * @throws Exception
     */
    public function createToken(): CSRFToken
    {
        $token = bin2hex(random_bytes(32));
        return new CSRFToken($token);
    }
}
