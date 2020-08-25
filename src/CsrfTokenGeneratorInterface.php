<?php


namespace Bermuda\Middleware;


interface CsrfTokenGeneratorInterface
{
    /**
     * @return string
     */
    public function generate(): string;
}
