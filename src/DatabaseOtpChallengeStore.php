<?php

declare(strict_types=1);

namespace Componenta\Auth\Otp;

use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\OnConflict;
use DateTimeImmutable;
use DateTimeZone;
use Psr\Clock\ClockInterface;

final readonly class DatabaseOtpChallengeStore implements OtpChallengeStoreInterface
{
    private const string CHALLENGE_TABLE = 'auth_otp_challenges';
    private const string BUDGET_TABLE = 'auth_otp_failure_budgets';
    private const string DATE_FORMAT = 'Y-m-d H:i:s.u';
    private const int MAX_CLEANUP = 10_000;

    public function __construct(
        private DatabaseInterface $database,
        private ClockInterface $clock,
    ) {}

    #[\Override]
    public function issue(
        OtpChallenge $challenge,
        #[\SensitiveParameter]
        string $verifier,
        OtpConfig $config,
    ): void {
        self::assertVerifier($verifier);

        $this->database->transaction(function () use (
            $challenge,
            $verifier,
            $config,
        ): void {
            $this->acquireBudgetLock(
                $challenge->subjectId,
                $challenge->purpose,
            );

            $latest = $this->database->select('created_at')
                ->from(self::CHALLENGE_TABLE)
                ->where('subject_uuid', $challenge->subjectId->toString())
                ->where('purpose', $challenge->purpose->value)
                ->where('channel', $challenge->channel->value)
                ->orderBy('created_at', 'DESC')
                ->limit(1)
                ->run()
                ->fetch();

            if (
                is_array($latest)
                && $config->resendCooldownSeconds > 0
                && $this->date(self::stringValue($latest, 'created_at'))
                    > $challenge->createdAt->modify(
                        sprintf('-%d seconds', $config->resendCooldownSeconds),
                    )
            ) {
                throw new OtpIssueThrottledException(
                    'OTP resend cooldown is active.',
                );
            }

            $cutoff = $challenge->createdAt->modify(
                sprintf('-%d seconds', $config->issueWindowSeconds),
            );
            $recentIssues = $this->database->select()
                ->from(self::CHALLENGE_TABLE)
                ->where('subject_uuid', $challenge->subjectId->toString())
                ->where('purpose', $challenge->purpose->value)
                ->where('channel', $challenge->channel->value)
                ->where('created_at', '>', $this->format($cutoff))
                ->count();

            if ($recentIssues >= $config->maxIssuesPerWindow) {
                throw new OtpIssueThrottledException(
                    'OTP issue budget is exhausted.',
                );
            }

            $this->database->update(self::CHALLENGE_TABLE)
                ->where('subject_uuid', $challenge->subjectId->toString())
                ->where('purpose', $challenge->purpose->value)
                ->where('binding', $challenge->binding)
                ->where('consumed_at', null)
                ->values([
                    'consumed_at' => $this->format($challenge->createdAt),
                ])
                ->run();

            $this->database->insert(self::CHALLENGE_TABLE)->values([
                'uuid' => $challenge->uuid->toString(),
                'subject_uuid' => $challenge->subjectId->toString(),
                'purpose' => $challenge->purpose->value,
                'channel' => $challenge->channel->value,
                'binding' => $challenge->binding,
                'verifier' => $verifier,
                'attempts' => 0,
                'max_attempts' => $config->maxAttempts,
                'created_at' => $this->format($challenge->createdAt),
                'expires_at' => $this->format($challenge->expiresAt),
                'consumed_at' => null,
            ])->run();
        });
    }

    #[\Override]
    public function verify(
        UuidInterface $challengeId,
        string $binding,
        #[\SensitiveParameter]
        string $verifier,
        OtpConfig $config,
    ): OtpVerification {
        self::assertVerifier($verifier);

        return $this->database->transaction(function () use (
            $challengeId,
            $binding,
            $verifier,
            $config,
        ): OtpVerification {
            $row = $this->database->select()
                ->from(self::CHALLENGE_TABLE)
                ->where('uuid', $challengeId->toString())
                ->run()
                ->fetch();

            if (!is_array($row)) {
                return OtpVerification::invalid();
            }

            $subjectId = Uuid::fromString(
                self::stringValue($row, 'subject_uuid'),
            );
            $purpose = new OtpPurpose(
                self::stringValue($row, 'purpose'),
            );
            $channel = new OtpChannel(
                self::stringValue($row, 'channel'),
            );
            $now = $this->now();

            $this->acquireBudgetLock($subjectId, $purpose);
            $this->resetExpiredBudget($subjectId, $purpose, $now, $config);

            if ($this->budgetReached($subjectId, $purpose, $config)) {
                return OtpVerification::rateLimited();
            }

            if (
                !hash_equals(self::stringValue($row, 'binding'), $binding)
                || ($row['consumed_at'] ?? null) !== null
                || $this->date(self::stringValue($row, 'expires_at')) <= $now
                || self::intValue($row, 'attempts')
                    >= self::intValue($row, 'max_attempts')
            ) {
                return OtpVerification::invalid();
            }

            if (
                hash_equals(
                    self::stringValue($row, 'verifier'),
                    $verifier,
                )
            ) {
                $affected = $this->database->update(self::CHALLENGE_TABLE)
                    ->where('uuid', $challengeId->toString())
                    ->where('binding', $binding)
                    ->where('verifier', $verifier)
                    ->where('consumed_at', null)
                    ->where('attempts', '<', self::intValue(
                        $row,
                        'max_attempts',
                    ))
                    ->where('expires_at', '>', $this->format($now))
                    ->values(['consumed_at' => $this->format($now)])
                    ->run();

                if ($affected !== 1) {
                    return OtpVerification::invalid();
                }

                $this->database->delete(self::BUDGET_TABLE)
                    ->where('subject_uuid', $subjectId->toString())
                    ->where('purpose', $purpose->value)
                    ->run();

                return OtpVerification::verified($subjectId, $channel);
            }

            $this->database->execute(
                'UPDATE ' . self::CHALLENGE_TABLE
                    . ' SET attempts = attempts + 1'
                    . ' WHERE uuid = ?'
                    . ' AND consumed_at IS NULL'
                    . ' AND attempts < max_attempts'
                    . ' AND expires_at > ?',
                [
                    $challengeId->toString(),
                    $this->format($now),
                ],
            );
            $failures = $this->recordFailure($subjectId, $purpose);

            return $failures >= $config->aggregateFailureLimit
                ? OtpVerification::rateLimited()
                : OtpVerification::invalid();
        });
    }

    #[\Override]
    public function revoke(UuidInterface $challengeId): void
    {
        $this->database->delete(self::CHALLENGE_TABLE)
            ->where('uuid', $challengeId->toString())
            ->run();
    }

    #[\Override]
    public function cleanup(int $limit = 1000): int
    {
        if ($limit < 1 || $limit > self::MAX_CLEANUP) {
            throw new \InvalidArgumentException(
                'OTP cleanup limit is out of bounds.',
            );
        }

        $now = $this->format($this->now());
        $rows = $this->database->select('uuid')
            ->from(self::CHALLENGE_TABLE)
            ->where(static function (mixed $query) use ($now): void {
                if (!$query instanceof \Cycle\Database\Query\SelectQuery) {
                    throw new \LogicException(
                        'Cycle must provide a SelectQuery.',
                    );
                }

                $query->where('expires_at', '<=', $now)
                    ->orWhere('consumed_at', '!=', null);
            })
            ->limit($limit)
            ->run()
            ->fetchAll();
        $ids = [];

        foreach ($rows as $row) {
            if (is_array($row) && is_string($row['uuid'] ?? null)) {
                $ids[] = $row['uuid'];
            }
        }

        return $ids === []
            ? 0
            : $this->database->delete(self::CHALLENGE_TABLE)
                ->where('uuid', 'IN', $ids)
                ->run();
    }

    private function acquireBudgetLock(
        UuidInterface $subjectId,
        OtpPurpose $purpose,
    ): void {
        $subject = $subjectId->toString();

        $this->database->insert(self::BUDGET_TABLE)->values([
            'subject_uuid' => $subject,
            'purpose' => $purpose->value,
            'failures' => 0,
            'window_started_at' => $this->format($this->now()),
            'lock_version' => 0,
        ])->onConflict(
            OnConflict::target('subject_uuid', 'purpose')->doNothing(),
        )->run();

        $affected = $this->database->execute(
            'UPDATE ' . self::BUDGET_TABLE
                . ' SET lock_version = lock_version + 1'
                . ' WHERE subject_uuid = ? AND purpose = ?',
            [$subject, $purpose->value],
        );

        if ($affected !== 1) {
            throw new \RuntimeException('Could not acquire OTP budget lock.');
        }
    }

    private function resetExpiredBudget(
        UuidInterface $subjectId,
        OtpPurpose $purpose,
        DateTimeImmutable $now,
        OtpConfig $config,
    ): void {
        $cutoff = $now->modify(
            sprintf('-%d seconds', $config->aggregateWindowSeconds),
        );

        $this->database->update(self::BUDGET_TABLE)
            ->where('subject_uuid', $subjectId->toString())
            ->where('purpose', $purpose->value)
            ->where('window_started_at', '<=', $this->format($cutoff))
            ->values([
                'failures' => 0,
                'window_started_at' => $this->format($now),
            ])
            ->run();
    }

    private function budgetReached(
        UuidInterface $subjectId,
        OtpPurpose $purpose,
        OtpConfig $config,
    ): bool {
        $row = $this->database->select('failures')
            ->from(self::BUDGET_TABLE)
            ->where('subject_uuid', $subjectId->toString())
            ->where('purpose', $purpose->value)
            ->run()
            ->fetch();

        return is_array($row)
            && self::intValue($row, 'failures')
                >= $config->aggregateFailureLimit;
    }

    private function recordFailure(
        UuidInterface $subjectId,
        OtpPurpose $purpose,
    ): int {
        $this->database->execute(
            'UPDATE ' . self::BUDGET_TABLE
                . ' SET failures = failures + 1'
                . ' WHERE subject_uuid = ? AND purpose = ?',
            [$subjectId->toString(), $purpose->value],
        );
        $row = $this->database->select('failures')
            ->from(self::BUDGET_TABLE)
            ->where('subject_uuid', $subjectId->toString())
            ->where('purpose', $purpose->value)
            ->run()
            ->fetch();

        if (!is_array($row)) {
            throw new \UnexpectedValueException(
                'OTP failure budget row disappeared.',
            );
        }

        return self::intValue($row, 'failures');
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }

    private function format(DateTimeImmutable $date): string
    {
        return $date->setTimezone(new DateTimeZone('UTC'))
            ->format(self::DATE_FORMAT);
    }

    private function date(string $value): DateTimeImmutable
    {
        $timezone = new DateTimeZone('UTC');

        foreach (['!Y-m-d H:i:s.u', '!Y-m-d H:i:s'] as $format) {
            $date = DateTimeImmutable::createFromFormat(
                $format,
                $value,
                $timezone,
            );

            if ($date instanceof DateTimeImmutable) {
                return $date;
            }
        }

        throw new \UnexpectedValueException(
            'Persisted OTP timestamp is invalid.',
        );
    }

    private static function assertVerifier(string $verifier): void
    {
        if (preg_match('/\A[a-f0-9]{64}\z/D', $verifier) !== 1) {
            throw new \InvalidArgumentException(
                'OTP verifier must be a SHA-256 MAC.',
            );
        }
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" is invalid.', $key),
            );
        }

        return (string) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function intValue(array $row, string $key): int
    {
        $value = $row[$key] ?? null;

        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" must be an integer.', $key),
            );
        }

        return (int) $value;
    }
}
