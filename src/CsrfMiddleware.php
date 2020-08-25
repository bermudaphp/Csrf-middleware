<?php


namespace Bermuda\Middleware;


use Dflydev\FigCookies\SetCookie;
use Dflydev\FigCookies\FigResponseCookies;
use Fig\Http\Message\RequestMethodInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;


/**
 * Class CsrfMiddleware
 * @package Bermuda\Middleware
 */
class CsrfMiddleware implements MiddlewareInterface
{
    /**
     * @var callable
     */
    protected $setCookie;
    protected CsrfTokenGeneratorInterface $generator;
    protected static ?string $token = null;

    private const methods = [
        RequestMethodInterface::METHOD_PUT,
        RequestMethodInterface::METHOD_POST,
        RequestMethodInterface::METHOD_PATCH,
        RequestMethodInterface::METHOD_DELETE,
    ];

    public const tokenKey = 'x-csrf-token';

    public function __construct(CsrfTokenGeneratorInterface $generator = null, array $cookieParams = [])
    {
        $this->generator = $generator ?? new CsrfTokenGenerator();
        $this->setCookie = static function (string $token) use ($cookieParams): SetCookie
        {
            return SetCookie::create(CsrfMiddleware::tokenKey, $token)
                ->withSecure($cookieParams['secure'] ?? true)
                ->withPath($cookieParams['path'] ?? '/')
                ->withHttpOnly($cookieParams['httpOnly'] ?? true)
                ->withDomain($cookieParams['domain'] ?? null)
                ->withExpires($cookieParams['lifetime'] ?? time() + (60 * 30));
        };
    }

    /**
     * @inheritDoc
     */
    public final function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array(strtoupper($request->getMethod()), self::methods))
        {
            if ((self::$token = $this->getFirstToken($request)) != null)
            {
                return $handler->handle($request);
            }

            return $this->setFirstToken($handler->handle($request), self::$token = $this->generator->generate());
        }

        if (($first = $this->getFirstToken($request)) == null
            || ($second = $this->getSecondToken($request)) !== $first)
        {
            throw CsrfException::new($first, $second ?? null);
        }

        return $handler->handle($request);
    }

    /**
     * @return string|null
     */
    public static function getToken():? string
    {
        return self::$token;
    }

    /**
     * @param ServerRequestInterface $request
     * @return string|null
     */
    protected function getFirstToken(ServerRequestInterface $request):? string
    {
        return $request->getCookieParams()[self::tokenKey] ?? null;
    }

    /**
     * @param ResponseInterface $response
     * @param string $token
     * @return ResponseInterface
     */
    protected function setFirstToken(ResponseInterface $response, string $token): ResponseInterface
    {
        return FigResponseCookies::set($response, ($this->setCookie)($token));
    }

    /**
     * @param ServerRequestInterface $request
     * @return string|null
     */
    protected function getSecondToken(ServerRequestInterface $request):? string
    {
        return ((array) $request->getParsedBody())[self::tokenKey] ?? null;
    }
}
