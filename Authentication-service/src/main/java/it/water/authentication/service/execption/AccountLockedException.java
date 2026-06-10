package it.water.authentication.service.execption;

import it.water.core.permission.exceptions.UnauthorizedException;

/**
 * @Author Aristide Cittadino
 * Login rejected because the account is temporarily locked out. Extends UnauthorizedException
 * so it surfaces as HTTP 401 without leaking whether the credentials were valid.
 */
public class AccountLockedException extends UnauthorizedException {

    private static final long serialVersionUID = 1L;

    private final long remainingLockMillis;

    public AccountLockedException(long remainingLockMillis) {
        super("Account temporarily locked due to too many failed login attempts");
        this.remainingLockMillis = remainingLockMillis;
    }

    public long getRemainingLockMillis() {
        return remainingLockMillis;
    }
}
