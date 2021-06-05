<?php


class CSRFTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     */
    public function testcsrf()
    {
        $factory = new \Gvera\Helpers\security\CSRFFactory();
        $token = $factory->createToken();
        $this->assertNotNull($token);
        $this->assertNotEmpty($token->getTokenValue());

    }
}