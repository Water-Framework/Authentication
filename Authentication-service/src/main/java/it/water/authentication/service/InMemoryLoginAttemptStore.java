package it.water.authentication.service;

import it.water.authentication.api.LoginAttemptStore;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.interceptors.annotations.FrameworkComponent;
import it.water.core.interceptors.annotations.Inject;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.ConcurrentHashMap;

/**
 * @Author Aristide Cittadino
 * Default in-process {@link LoginAttemptStore}: counts failures in a sliding window, locks the
 * key after {@code threshold} failures, resets on success. State is per-JVM — multi-node
 * deployments need a shared implementation.
 */
@Slf4j
@FrameworkComponent
public class InMemoryLoginAttemptStore implements LoginAttemptStore {

    private static final int DEFAULT_THRESHOLD = 5;
    private static final long DEFAULT_WINDOW_MILLIS = 15L * 60L * 1000L;   // 15 minutes
    private static final long DEFAULT_LOCKOUT_MILLIS = 15L * 60L * 1000L;  // 15 minutes
    //hard cap on tracked keys to bound memory against credential-stuffing on arbitrary usernames
    private static final int DEFAULT_MAX_KEYS = 100000;
    //#34 - progressive backoff defaults
    private static final boolean DEFAULT_BACKOFF_ENABLED = true;
    private static final int DEFAULT_BACKOFF_MULTIPLIER = 2;               // exponential
    private static final long DEFAULT_MAX_LOCKOUT_MILLIS = 60L * 60L * 1000L; // 1 hour safety cap

    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();

    @Inject
    @Setter
    private ApplicationProperties applicationProperties;

    /**
     * Per-key counter. Synchronization is encapsulated here (instance methods lock on {@code this}),
     * so callers never synchronize on a parameter or a field they don't own.
     */
    private static final class Attempt {
        private int failures;
        private long windowStart;
        private long lockedUntil;
        //last time this entry was written; used by both eviction strategies
        private long lastUpdate;
        //#34 - how many times this key has already been locked; drives the progressive backoff
        private int lockoutCount;
        //#34 - lockout duration actually applied on the last lock, exposed for logging
        private long lastAppliedLockoutMillis;

        /**
         * An entry is stale (safe to drop) once it is no longer locked AND its failure window has
         * expired: from that moment it carries no security state and only consumes memory.
         */
        synchronized boolean isStale(long now, long windowMillis) {
            return lockedUntil <= now && (now - windowStart) > windowMillis;
        }

        synchronized long lastUpdate() {
            return lastUpdate;
        }

        synchronized boolean isLocked(long now) {
            return lockedUntil > now;
        }

        synchronized long remainingLockMillis(long now) {
            return Math.max(lockedUntil - now, 0L);
        }

        //#34 - lockout duration actually applied on the last lock, for logging by the caller
        synchronized long lastAppliedLockoutMillis() {
            return lastAppliedLockoutMillis;
        }

        /**
         * Applies one failure within the sliding window and locks the key once the threshold is
         * reached. Returns the current failure count so the caller can log the lockout.
         * <p>
         * #34 - when the threshold is reached the lockout duration grows progressively: starting from
         * {@code lockoutMillis}, it is multiplied by {@code multiplier} once per previous lockout of
         * this key ({@code lockoutCount}), capped at {@code maxLockoutMillis}. The growth uses an
         * iterative loop that stops as soon as the cap is reached, so {@code long} can never overflow.
         * After locking, {@code failures}/{@code windowStart} are reset so a fresh failure cycle can
         * start once the lock expires and the backoff keeps escalating ({@code lockoutCount} persists
         * until the entry is evicted or cleared by a successful login).
         */
        synchronized int recordFailure(long now, long windowMillis, int threshold, long lockoutMillis,
                                       boolean backoffEnabled, int multiplier, long maxLockoutMillis) {
            // if window expired, restart it
            if (now - windowStart > windowMillis) {
                windowStart = now;
                failures = 0;
            }
            failures++;
            lastUpdate = now;
            if (failures >= threshold) {
                long duration = computeBackoffDuration(lockoutMillis, backoffEnabled, multiplier, maxLockoutMillis);
                lockedUntil = now + duration;
                lastAppliedLockoutMillis = duration;
                lockoutCount++;
                //#34 - reset the failure cycle so a new round of failures restarts after the lock expires
                failures = 0;
                windowStart = now;
            }
            return failures;
        }

        /**
         * #34 - computes the progressive lockout duration. Multiplies the base duration by
         * {@code multiplier} once per previous lockout, checking the cap at every iteration so the
         * accumulation never overflows {@code long}.
         */
        private long computeBackoffDuration(long lockoutMillis, boolean backoffEnabled, int multiplier, long maxLockoutMillis) {
            if (!backoffEnabled)
                return Math.min(lockoutMillis, maxLockoutMillis);
            long duration = lockoutMillis;
            if (duration >= maxLockoutMillis)
                return maxLockoutMillis;
            for (int i = 0; i < lockoutCount; i++) {
                duration *= multiplier;
                if (duration >= maxLockoutMillis)
                    return maxLockoutMillis;
            }
            return duration;
        }
    }

    private int maxKeys() {
        return intProp(AuthenticationConstants.LOGIN_LOCKOUT_MAX_KEYS, DEFAULT_MAX_KEYS);
    }

    private boolean isStale(Attempt a, long now) {
        return a.isStale(now, windowMillis());
    }

    /**
     * Opportunistic, bounded cleanup invoked on writes:
     * 1) drop entries whose window expired and are not locked;
     * 2) if still above the cap, evict the least-recently-updated entries until under the cap.
     * Locked entries are preserved as long as possible so eviction can never silently unlock a key.
     */
    private void evictIfNeeded() {
        long now = now();
        // pass 1: remove stale entries (no live security state)
        attempts.entrySet().removeIf(e -> isStale(e.getValue(), now));
        int cap = maxKeys();
        if (attempts.size() <= cap)
            return;
        // pass 2: cap enforcement — evict oldest (least-recently-updated) first
        attempts.entrySet().stream()
                .sorted((x, y) -> Long.compare(lastUpdateOf(x.getValue()), lastUpdateOf(y.getValue())))
                .limit((long) attempts.size() - cap)
                .map(java.util.Map.Entry::getKey)
                .forEach(attempts::remove);
        log.warn("Login attempt store exceeded {} keys; evicted oldest entries down to the cap", cap);
    }

    private long lastUpdateOf(Attempt a) {
        return a.lastUpdate();
    }

    private int threshold() {
        return intProp(AuthenticationConstants.LOGIN_LOCKOUT_THRESHOLD, DEFAULT_THRESHOLD);
    }

    private long windowMillis() {
        return longProp(AuthenticationConstants.LOGIN_LOCKOUT_WINDOW_MILLIS, DEFAULT_WINDOW_MILLIS);
    }

    private long lockoutMillis() {
        return longProp(AuthenticationConstants.LOGIN_LOCKOUT_DURATION_MILLIS, DEFAULT_LOCKOUT_MILLIS);
    }

    //#34 - whether the lockout duration grows progressively across repeated lockouts of the same key
    private boolean backoffEnabled() {
        return boolProp(AuthenticationConstants.LOGIN_LOCKOUT_BACKOFF_ENABLED, DEFAULT_BACKOFF_ENABLED);
    }

    //#34 - exponential growth factor; clamped to a minimum of 1 to avoid shrinking/zeroing the duration
    private int backoffMultiplier() {
        int multiplier = intProp(AuthenticationConstants.LOGIN_LOCKOUT_BACKOFF_MULTIPLIER, DEFAULT_BACKOFF_MULTIPLIER);
        return Math.max(multiplier, 1);
    }

    //#34 - hard ceiling on the lockout duration; never below the base lockout duration (used as a floor)
    private long maxLockoutMillis() {
        long max = longProp(AuthenticationConstants.LOGIN_LOCKOUT_MAX_DURATION_MILLIS, DEFAULT_MAX_LOCKOUT_MILLIS);
        long base = lockoutMillis();
        return Math.max(max, base);
    }

    @Override
    public boolean isLocked(String key) {
        if (key == null)
            return false;
        Attempt a = attempts.get(key);
        return a != null && a.isLocked(now());
    }

    @Override
    public void recordFailure(String key) {
        if (key == null)
            return;
        long now = now();
        //bound memory before inserting a potentially-new key (credential stuffing on random usernames)
        evictIfNeeded();
        Attempt a = attempts.computeIfAbsent(key, k -> {
            Attempt na = new Attempt();
            na.windowStart = now;
            return na;
        });
        int threshold = threshold();
        long lockoutMillis = lockoutMillis();
        //#34 - recordFailure resets failures to 0 when it locks, so detect a lock via the live lock state
        int failures = a.recordFailure(now, windowMillis(), threshold, lockoutMillis,
                backoffEnabled(), backoffMultiplier(), maxLockoutMillis());
        if (failures == 0 && a.isLocked(now)) {
            log.warn("Login lockout triggered for key '{}'; locked for {} ms", key, a.lastAppliedLockoutMillis());
        }
    }

    @Override
    public void recordSuccess(String key) {
        if (key == null)
            return;
        attempts.remove(key);
    }

    @Override
    public long remainingLockMillis(String key) {
        if (key == null)
            return 0L;
        Attempt a = attempts.get(key);
        return a == null ? 0L : a.remainingLockMillis(now());
    }

    private long now() {
        return System.currentTimeMillis();
    }

    private int intProp(String key, int def) {
        if (applicationProperties == null)
            return def;
        Object raw = applicationProperties.getProperty(key);
        if (raw == null)
            return def;
        try {
            return Integer.parseInt(raw.toString().trim());
        } catch (NumberFormatException e) {
            log.warn("Invalid int property {} ('{}'), using default {}", key, raw, def);
            return def;
        }
    }

    private long longProp(String key, long def) {
        if (applicationProperties == null)
            return def;
        Object raw = applicationProperties.getProperty(key);
        if (raw == null)
            return def;
        try {
            return Long.parseLong(raw.toString().trim());
        } catch (NumberFormatException e) {
            log.warn("Invalid long property {} ('{}'), using default {}", key, raw, def);
            return def;
        }
    }

    //#34 - boolean property reader, mirroring intProp/longProp
    private boolean boolProp(String key, boolean def) {
        if (applicationProperties == null)
            return def;
        Object raw = applicationProperties.getProperty(key);
        if (raw == null)
            return def;
        return Boolean.parseBoolean(raw.toString().trim());
    }
}
