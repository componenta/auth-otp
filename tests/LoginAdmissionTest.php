<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Denied\DeniedReason;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Http\PayloadStorageInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class LoginAdmissionTest extends TestCase
{
    public function testFinalAdmissionDenialCannotPublishASession(): void
    {
        $uuids = new UuidFactory();
        $identity = new readonly class($uuids->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $proof = new AuthenticationEvidence(['otp.email']);
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(new AuthenticationResult($identity, evidence: $proof));
        $provider = $this->createStub(IdentityProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        $denial = new DeniedReason('user_disabled');
        $guard->method('check')->willReturn($denial);
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::never())->method('create');
        $sessions->expects(self::never())->method('isGrantCurrent');
        $policies = $this->createMock(AuthSessionPolicyProviderInterface::class);
        $policies->expects(self::never())->method('for');
        $storage = $this->createMock(PayloadStorageInterface::class);
        $storage->expects(self::never())->method('store');
        $now = new \DateTimeImmutable('2030-01-01T00:00:00+00:00');
        $transaction = new PreAuthenticationTransaction($uuids->generate(), $now, $now->modify('+5 minutes'));
        $transactions = $this->createStub(PreAuthenticationManagerInterface::class);
        $transactions->method('verify')->willReturn($transaction);
        $transactions->method('consume')->willReturn($transaction);
        $metadata = $this->createStub(SessionMetadataExtractorInterface::class);
        $metadata->method('extract')->willReturn([]);
        $denied = $this->createMock(DeniedResponseFactoryInterface::class);
        $denied->expects(self::once())->method('create')->with($denial)->willReturn(new Response(401));
        $cookies = new PreAuthenticationCookieTransport();
        $handler = new \Componenta\Auth\Otp\OtpLoginVerifyHandler(
            new \Componenta\Auth\Otp\OtpExtractor(), $authenticator,
            new PreAuthenticationConsumer($transactions, $cookies), new PreAuthenticationGrantPublisher($cookies),
            new AuthenticatedSessionIssuer($sessions, $policies, new AuthenticationAdmission($provider, $guard)),
            new AuthSessionGrantPublisher($sessions, $storage), $metadata, $denied, new Psr17Factory(),
        );
        $request = (new ServerRequest('POST', 'https://example.test/login'))
            ->withCookieParams(['__Host-auth_pre' => PreAuthenticationCredential::generate()->toString()])
            ->withHeader('X-Pre-Auth-Token', PreAuthenticationRequestToken::generate()->toString())
            ->withParsedBody(['challenge_id' => $uuids->generate()->toString(), 'code' => '123456']);
        $response = $handler->handle($request);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('', (string) $response->getBody());
        self::assertStringContainsString('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertStringNotContainsString('__Host-auth_session=', $response->getHeaderLine('Set-Cookie'));
    }
}
