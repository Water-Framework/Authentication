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

    private final ConcurrentHashMap<String, Attempt> attempts = new ConcurrentHashMap<>();

    @Inject
    @Setter
    private ApplicationProperties applicationProperties;

    private static final class Attempt {
        private int failures;
        private long windowStart;
        private long lockedUntil;
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

    @Override
    public boolean isLocked(String key) {
        if (key == null)
            return false;
        Attempt a = attempts.get(key);
        if (a == null)
            return false;
        synchronized (a) {
            return a.lockedUntil > now();
        }
    }

    @Override
    public void recordFailure(String key) {
        if (key == null)
            return;
        long now = now();
        Attempt a = attempts.computeIfAbsent(key, k -> {
            Attempt na = new Attempt();
            na.windowStart = now;
            return na;
        });
        synchronized (a) {
            // if window expired, restart it
            if (now - a.windowStart > windowMillis()) {
                a.windowStart = now;
                a.failures = 0;
            }
            a.failures++;
            if (a.failures >= threshold()) {
                a.lockedUntil = now + lockoutMillis();
                log.warn("Login lockout triggered for key '{}' after {} failures; locked for {} ms", key, a.failures, lockoutMillis());
            }
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
        if (a == null)
            return 0L;
        synchronized (a) {
            long remaining = a.lockedUntil - now();
            return Math.max(remaining, 0L);
        }
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
}
