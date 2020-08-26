<?php


namespace Bermuda\Middleware;


/**
 * @return string
 */
function csrf_field(): string
{
    return '<input type="hidden" name="'. CsrfMiddleware::tokenKey .'" value="'. CsrfMiddleware::getToken() .'">';
}

/**
 * @return string
 */
function csrf_token(): string
{
    return CsrfMiddleware::getToken();
}
