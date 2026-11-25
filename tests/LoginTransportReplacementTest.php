<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Otp\OtpExtractor;
use Componenta\Auth\Otp\OtpLoginVerifyHandler;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionGrant;
use Componenta\Auth\Session\AuthSessionManagerInterface;
use Componenta\Auth\Session\AuthSessionPolicy;
use Componenta\Auth\Session\AuthSessionPolicyProviderInterface;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationCookieTransport;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\SessionCookieTransport;
use Componenta\Auth\Session\Http\SessionCredentialPayload;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Componenta\Auth\Session\PreAuthenticationCredential;
use Componenta\Auth\Session\PreAuthenticationManagerInterface;
use Componenta\Auth\Session\PreAuthenticationRequestToken;
use Componenta\Auth\Session\PreAuthenticationTransaction;
use Componenta\Auth\Session\SessionCredential;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use DateTimeImmutable;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LoginTransportReplacementTest extends TestCase
{
    /** @return iterable<string, array{bool}> */
    public static function pendingGrants(): iterable
    {
        yield 'no pending grant' => [false];
        yield 'pending upstream grant' => [true];
    }

    #[DataProvider('pendingGrants')]
    public function testSuccessfulLoginPublishesOnlyItsNewCredential(bool $hasPendingGrant): void
    {
        $uuids = new UuidFactory();
        $identity = new readonly class($uuids->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $proof = new AuthenticationEvidence(['otp.email']);
        $now = new DateTimeImmutable('2030-01-01T00:00:00Z');
        $grant = new AuthSessionGrant(
            new AuthSession($uuids->generate(), $identity->uuid, $proof, 1, $now, null, $now, $now->modify('+1 hour'), $now->modify('+8 hours')),
            SessionCredential::generate(),
        );
        $authenticator = $this->createStub(AuthenticatorInterface::class);
        $authenticator->method('attempt')->willReturn(new AuthenticationResult($identity, evidence: $proof));
        $identities = $this->createStub(IdentityProviderInterface::class);
        $identities->method('findByUuid')->willReturn($identity);
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        $guard->method('check')->willReturn(null);
        $sessions = $this->createMock(AuthSessionManagerInterface::class);
        $sessions->expects(self::once())->method('create')->willReturn($grant);
        $sessions->expects(self::once())->method('isGrantCurrent')->with($grant)->willReturn(true);
        $policies = $this->createStub(AuthSessionPolicyProviderInterface::class);
        $policies->method('for')->willReturn(new AuthSessionPolicy(3600, 28800));
        $transaction = new PreAuthenticationTransaction($uuids->generate(), $now, $now->modify('+5 minutes'));
        $transactions = $this->createStub(PreAuthenticationManagerInterface::class);
        $transactions->method('verify')->willReturn($transaction);
        $transactions->method('consume')->willReturn($transaction);
        $metadata = $this->createStub(SessionMetadataExtractorInterface::class);
        $metadata->method('extract')->willReturn([]);
        $denied = $this->createMock(DeniedResponseFactoryInterface::class);
        $denied->expects(self::never())->method('create');
        $cookies = new PreAuthenticationCookieTransport();
        $storage = new SessionCookieTransport();
        $state = new CredentialTransportState();
        $pending = SessionCredential::generate();
        $discarded = 0;

        if ($hasPendingGrant) {
            $state->queue($storage, new SessionCredentialPayload($pending));
            $state->onDiscard(static function () use (&$discarded): void {
                ++$discarded;
            });
        }

        $handler = new OtpLoginVerifyHandler(
            new OtpExtractor(), $authenticator,
            new PreAuthenticationConsumer($transactions, $cookies), new PreAuthenticationGrantPublisher($cookies),
            new AuthenticatedSessionIssuer($sessions, $policies, new AuthenticationAdmission($identities, $guard)),
            new AuthSessionGrantPublisher($sessions, $storage), $metadata, $denied, new Psr17Factory(),
        );
        $request = (new ServerRequest('POST', 'https://example.test/login'))
            ->withAttribute(CredentialTransportState::class, $state)
            ->withCookieParams(['__Host-auth_pre' => PreAuthenticationCredential::generate()->toString()])
            ->withHeader('X-Pre-Auth-Token', PreAuthenticationRequestToken::generate()->toString())
            ->withParsedBody(['challenge_id' => $uuids->generate()->toString(), 'code' => '123456']);

        $response = $handler->handle($request);
        // This is the same public completion step used by AuthenticationMiddleware.
        $published = $state->apply($request, $response);

        self::assertSame(204, $published->getStatusCode());
        self::assertStringContainsString($grant->credential->toString(), $published->getHeaderLine('Set-Cookie'));
        self::assertStringNotContainsString($pending->toString(), $published->getHeaderLine('Set-Cookie'));
        self::assertSame($hasPendingGrant ? 1 : 0, $discarded);
    }
}
