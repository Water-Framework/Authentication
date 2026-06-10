package it.water.authentication.api;

import it.water.core.api.service.Service;

/**
 * @Author Aristide Cittadino
 * Tracks failed login attempts per principal (key = issuer + username) and decides when an
 * account is temporarily locked out. Default impl is in-memory; multi-node deployments can
 * plug a shared store (e.g. Redis/JDBC).
 */
public interface LoginAttemptStore extends Service {

    /**
     * @return true if the key is currently locked out
     */
    boolean isLocked(String key);

    /**
     * Records a failed login attempt for the key.
     */
    void recordFailure(String key);

    /**
     * Records a successful login, clearing accumulated failures for the key.
     */
    void recordSuccess(String key);

    /**
     * @return remaining lockout time in milliseconds, or 0 if not locked
     */
    long remainingLockMillis(String key);
}
