<?php


namespace Bermuda\Middleware;


/**
 * Class CsrfTokenGenerator
 * @package Bermuda\Middleware
 */
class CsrfTokenGenerator implements CsrfTokenGeneratorInterface
{
    private int $length;

    public function __construct(int $length = 32)
    {
        $this->length = $length;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function generate(): string
    {
        return bin2hex(random_bytes($this->length / 2));
    }
}
