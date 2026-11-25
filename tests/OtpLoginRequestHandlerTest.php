<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\Otp\OtpLoginRequestHandler;
use Componenta\Auth\Otp\OtpRequest;
use Componenta\Auth\Otp\OtpRequestQueueInterface;
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationGrant;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidFactoryInterface;
use DateTimeImmutable;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Stream;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

final class OtpLoginRequestHandlerTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function responseStreams(): iterable
    {
        foreach (['complete', 'partial', 'stalled', 'throwing'] as $mode) {
            yield $mode => [$mode];
        }
    }

    #[DataProvider('responseStreams')]
    public function testCompleteBodyIsPreparedBeforeCreatingOrQueuingAGrant(string $mode): void
    {
        $grant = self::grant();
        $created = 0;
        $queued = 0;
        $manager = $this->createStub(PreAuthenticationManagerInterface::class);
        $manager->method('create')->willReturnCallback(static function () use (&$created, $grant): PreAuthenticationGrant {
            ++$created;

            return $grant;
        });
        $queue = $this->createStub(OtpRequestQueueInterface::class);
        $queue->method('enqueue')->willReturnCallback(static function () use (&$queued): void {
            ++$queued;
        });
        $sink = new class {
            public string $body = '';
            public int $calls = 0;
        };
        $failure = new \RuntimeException('Synthetic stream failure.');
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(static function (string $bytes) use ($sink, $mode, $failure): int {
            if (++$sink->calls > 1) {
                if ($mode === 'stalled') {
                    return 0;
                }
                if ($mode === 'throwing') {
                    throw $failure;
                }
            }

            $written = $mode === 'complete' ? strlen($bytes) : min(7, strlen($bytes));
            $sink->body .= substr($bytes, 0, $written);

            return $written;
        });
        $stream->method('__toString')->willReturnCallback(static fn(): string => $sink->body);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn(new Response(200, [], $stream));
        $failureObserved = null;
        $response = null;

        try {
            $response = $this->handler($manager, $queue, $responses)->handle(self::request());
        } catch (\RuntimeException $exception) {
            $failureObserved = $exception;
        }

        if (in_array($mode, ['stalled', 'throwing'], true)) {
            self::assertInstanceOf(\RuntimeException::class, $failureObserved, 'Incomplete response must not be returned as success.');
            self::assertNull($response);
            self::assertSame(0, $created);
            self::assertSame(0, $queued);
            if ($mode === 'throwing') {
                self::assertSame($failure, $failureObserved);
            }

            return;
        }

        self::assertNull($failureObserved);
        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertSame(200, $response->getStatusCode());
        self::assertJson((string) $response->getBody());
        self::assertArrayHasKey('challenge_id', json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR));
        self::assertSame(1, $created);
        self::assertSame(1, $queued);
    }

    /** @return iterable<string, array{string}> */
    public static function failedPublicationHeaders(): iterable
    {
        yield 'cookie' => ['Set-Cookie'];
        yield 'request token' => ['X-Pre-Auth-Token'];
        yield 'cache policy' => ['Pragma'];
    }

    #[DataProvider('failedPublicationHeaders')]
    public function testPublicationFailureConsumesCreatedPreAuthGrant(string $failedHeader): void
    {
        $grant = self::grant();
        $created = false;
        $manager = $this->createMock(PreAuthenticationManagerInterface::class);
        $manager->expects(self::once())->method('create')
            ->willReturnCallback(static function () use (&$created, $grant): PreAuthenticationGrant {
                $created = true;

                return $grant;
            });
        $manager->expects(self::once())->method('consume')
            ->with($grant->credential, $grant->requestToken)
            ->willReturn($grant->transaction);
        $queue = $this->createMock(OtpRequestQueueInterface::class);
        $queue->expects(self::never())->method('enqueue');
        $failure = new \RuntimeException('response publication failed');
        $response = $this->createStub(ResponseInterface::class);
        $response->method('getBody')->willReturn(Stream::create(''));
        $response->method('getHeader')->willReturn([]);
        $response->method('withoutHeader')->willReturnSelf();
        $writeHeader = static function (string $name, mixed $value) use (
            &$created,
            $failedHeader,
            $failure,
            $response,
        ): ResponseInterface {
            if ($created && $name === $failedHeader) {
                throw $failure;
            }

            return $response;
        };
        $response->method('withHeader')->willReturnCallback($writeHeader);
        $response->method('withAddedHeader')->willReturnCallback($writeHeader);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn($response);

        try {
            $this->handler($manager, $queue, $responses)->handle(self::request());
            self::fail('The response failure must be propagated.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }
    }

    public function testSuccessKeepsBrowserGrantAndQueuesMatchingBinding(): void
    {
        $grant = self::grant();
        $manager = $this->createMock(PreAuthenticationManagerInterface::class);
        $manager->expects(self::once())->method('create')->willReturn($grant);
        $manager->expects(self::never())->method('consume');
        $queue = $this->createMock(OtpRequestQueueInterface::class);
        $queue->expects(self::once())->method('enqueue')
            ->with(self::callback(static fn(OtpRequest $work): bool =>
                $work->binding === $grant->transaction->uuid->toString()
                && $work->identity === 'user@example.test'));

        $response = $this->handler($manager, $queue, new Psr17Factory())->handle(self::request());

        self::assertSame(200, $response->getStatusCode());
        self::assertSame($grant->requestToken->toString(), $response->getHeaderLine('X-Pre-Auth-Token'));
        self::assertStringContainsString('__Host-auth_pre=', $response->getHeaderLine('Set-Cookie'));
    }

    public function testQueueFailureConsumesCreatedPreAuthGrant(): void
    {
        $grant = self::grant();
        $manager = $this->createMock(PreAuthenticationManagerInterface::class);
        $manager->expects(self::once())->method('create')->willReturn($grant);
        $manager->expects(self::once())->method('consume')
            ->with($grant->credential, $grant->requestToken)
            ->willReturn($grant->transaction);
        $failure = new \RuntimeException('queue failed');
        $queue = $this->createMock(OtpRequestQueueInterface::class);
        $queue->expects(self::once())->method('enqueue')->willThrowException($failure);

        try {
            $this->handler($manager, $queue, new Psr17Factory())->handle(self::request());
            self::fail('The queue failure must be propagated.');
        } catch (\RuntimeException $exception) {
            self::assertSame($failure, $exception);
        }
    }

    private function handler(
        PreAuthenticationManagerInterface $manager,
        OtpRequestQueueInterface $queue,
        ResponseFactoryInterface $responses,
    ): OtpLoginRequestHandler {
        $uuids = $this->createStub(UuidFactoryInterface::class);
        $uuids->method('generate')->willReturn(Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789def'));

        return new OtpLoginRequestHandler(
            $manager,
            new PreAuthenticationGrantPublisher(new PreAuthenticationCookieTransport()),
            $queue,
            $uuids,
            $responses,
        );
    }

    private static function request(): ServerRequest
    {
        return (new ServerRequest('POST', '/otp'))
            ->withParsedBody(['identity' => 'user@example.test']);
    }

    private static function grant(): PreAuthenticationGrant
    {
        $created = new DateTimeImmutable('2030-01-01T00:00:00+00:00');

        return new PreAuthenticationGrant(
            new PreAuthenticationTransaction(
                Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc'),
                $created,
                $created->modify('+10 minutes'),
            ),
            PreAuthenticationCredential::fromBytes(str_repeat('a', 32)),
            PreAuthenticationRequestToken::fromBytes(str_repeat('b', 32)),
        );
    }
}
