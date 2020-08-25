<?php


namespace Bermuda\Middleware;


class CsrfException extends \RuntimeException
{
    protected ?string $firstToken = null;
    protected ?string $secondToken = null;

    public static function new(?string $firstToken, ?string $secondToken): self
    {
        $instance = new static('Csrf Token missing or invalid');
        $instance->firstToken = $firstToken;
        $instance->secondToken = $secondToken;

        return $instance;
    }
}
