<?php

declare(strict_types=1);

namespace Zephyr\Authorization;

/**
 * Authorization Exception
 *
 * Thrown when a user is not authorized to perform an action.
 */
class AuthorizationException extends \Exception
{
    /** @var int HTTP status code */
    protected int $statusCode = 403;

    /** @var string|null The ability that was denied */
    protected ?string $ability = null;

    /**
     * Create a new authorization exception
     *
     * @param string $message The error message
     * @param string|null $ability The ability that was denied
     */
    public function __construct(string $message = 'This action is unauthorized.', ?string $ability = null)
    {
        parent::__construct($message);
        $this->ability = $ability;
    }

    /**
     * Get the HTTP status code
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Set the HTTP status code
     */
    public function setStatusCode(int $code): self
    {
        $this->statusCode = $code;
        return $this;
    }

    /**
     * Get the denied ability
     */
    public function getAbility(): ?string
    {
        return $this->ability;
    }

    /**
     * Create a denied response
     */
    public static function denied(string $message = 'This action is unauthorized.'): self
    {
        return new self($message);
    }

    /**
     * Create a not found response (for hiding existence)
     */
    public static function notFound(string $message = 'Resource not found.'): self
    {
        $exception = new self($message);
        $exception->setStatusCode(404);
        return $exception;
    }
}
