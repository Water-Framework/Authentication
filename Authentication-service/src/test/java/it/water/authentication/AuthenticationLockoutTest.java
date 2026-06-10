/*
 * Copyright 2024 Aristide Cittadino
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package it.water.authentication;

import it.water.authentication.api.AuthenticationSystemApi;
import it.water.authentication.api.LoginAttemptStore;
import it.water.authentication.service.execption.AccountLockedException;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.api.service.Service;
import it.water.core.interceptors.annotations.Inject;
import it.water.core.permission.exceptions.UnauthorizedException;
import it.water.core.testing.utils.junit.WaterTestExtension;
import lombok.Setter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Properties;

/**
 * Regression tests for H8 — login lockout in AuthenticationSystemServiceImpl.
 * Lockout is disabled under {@code water.testMode=true}, so each test temporarily overrides it
 * to false and restores the original value afterwards. Test account: admin/admin.
 */
@ExtendWith(WaterTestExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthenticationLockoutTest implements Service {

    private static final int LOCKOUT_THRESHOLD = 3;
    private static final long LOCKOUT_WINDOW_MILLIS = 30_000L;
    private static final long LOCKOUT_DURATION_MILLIS = 30_000L;

    private static final String VALID_USER = "admin";
    private static final String VALID_PWD = "admin";
    private static final String WRONG_PWD = "ThisIsDefinitelyWrong!99";
    private static final String TEST_ISSUER = "it.water.core.api.model.User";

    @Inject
    @Setter
    private AuthenticationSystemApi authenticationSystemApi;

    @Inject
    @Setter
    private LoginAttemptStore loginAttemptStore;

    @Inject
    @Setter
    private ApplicationProperties applicationProperties;

    // Helper: enable / disable lockout and configure low thresholds

    private void enableLockout() {
        Properties props = new Properties();
        props.put("water.testMode", "false");
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOCKOUT_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(LOCKOUT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(LOCKOUT_DURATION_MILLIS));
        applicationProperties.loadProperties(props);
    }

    private void disableLockout() {
        Properties props = new Properties();
        props.put("water.testMode", "true");
        applicationProperties.loadProperties(props);
    }

    /**
     * Resets the attempt store for the test key so tests don't bleed into each other.
     */
    private void clearAttempts(String username) {
        loginAttemptStore.recordSuccess(TEST_ISSUER + ":" + username);
    }

    // H8-1  Lockout disabled in testMode=true — existing tests must stay safe

    @Test
    @Order(1)
    void loginTestModeTrueLockoutNeverTriggered() {
        // testMode is true (default from it.water.application.properties)
        // Perform more failures than LOCKOUT_THRESHOLD without ever hitting AccountLockedException
        String uniqueUser = "nonExistingUser_" + System.nanoTime();
        for (int i = 0; i < LOCKOUT_THRESHOLD + 5; i++) {
            try {
                authenticationSystemApi.login(uniqueUser, WRONG_PWD, TEST_ISSUER);
            } catch (AccountLockedException e) {
                Assertions.fail("AccountLockedException must NEVER be thrown when water.testMode=true");
            } catch (UnauthorizedException ignored) {
                // expected — wrong credentials
            }
        }
    }

    // H8-2  AccountLockedException is thrown after N failures (testMode=false)

    @Test
    @Order(2)
    void loginTestModeFalseAccountLockedAfterThresholdFailures() {
        enableLockout();
        String uniqueUser = "lockoutSubject_" + System.nanoTime();
        try {
            // Exhaust the threshold
            for (int i = 0; i < LOCKOUT_THRESHOLD; i++) {
                try {
                    authenticationSystemApi.login(uniqueUser, WRONG_PWD, TEST_ISSUER);
                } catch (UnauthorizedException ignored) {
                    // expected wrong-credentials — accumulates the counter
                }
            }
            // The next attempt must trigger AccountLockedException
            Assertions.assertThrows(AccountLockedException.class,
                    () -> authenticationSystemApi.login(uniqueUser, WRONG_PWD, TEST_ISSUER),
                    "login() must throw AccountLockedException after " + LOCKOUT_THRESHOLD + " consecutive failures");
        } finally {
            clearAttempts(uniqueUser);
            disableLockout();
        }
    }

    // H8-3  AccountLockedException message is generic (no info leakage)

    @Test
    @Order(3)
    void loginAccountLockedExceptionMessageIsGeneric() {
        enableLockout();
        String uniqueUser = "messageCheckUser_" + System.nanoTime();
        try {
            for (int i = 0; i < LOCKOUT_THRESHOLD; i++) {
                try {
                    authenticationSystemApi.login(uniqueUser, WRONG_PWD, TEST_ISSUER);
                } catch (UnauthorizedException ignored) { /* expected */ }
            }

            AccountLockedException ex = Assertions.assertThrows(AccountLockedException.class,
                    () -> authenticationSystemApi.login(uniqueUser, WRONG_PWD, TEST_ISSUER));

            String message = ex.getMessage();
            Assertions.assertNotNull(message, "Exception message must not be null");
            // Message must not reveal whether the account exists or what the real cause is
            Assertions.assertFalse(message.toLowerCase().contains("password"),
                    "Lockout message must not mention 'password' to avoid info leakage");
            Assertions.assertFalse(message.toLowerCase().contains("invalid credentials"),
                    "Lockout message must not reveal credential validity");
            // Verify the remaining-lock accessor returns a positive value
            Assertions.assertTrue(ex.getRemainingLockMillis() > 0,
                    "AccountLockedException.getRemainingLockMillis() must be positive");
        } finally {
            clearAttempts(uniqueUser);
            disableLockout();
        }
    }

    // H8-4  Successful login resets the failure counter

    @Test
    @Order(4)
    void loginSuccessfulLoginResetsFailureCounter() {
        enableLockout();
        try {
            // Accumulate (threshold - 1) failures
            for (int i = 0; i < LOCKOUT_THRESHOLD - 1; i++) {
                try {
                    authenticationSystemApi.login(VALID_USER, WRONG_PWD, TEST_ISSUER);
                } catch (UnauthorizedException ignored) { /* expected */ }
            }

            // Successful login must reset the counter
            Assertions.assertDoesNotThrow(
                    () -> authenticationSystemApi.login(VALID_USER, VALID_PWD, TEST_ISSUER),
                    "A successful login must not throw");

            // The next (threshold - 1) failures must NOT lock (counter was reset)
            for (int i = 0; i < LOCKOUT_THRESHOLD - 1; i++) {
                try {
                    authenticationSystemApi.login(VALID_USER, WRONG_PWD, TEST_ISSUER);
                } catch (AccountLockedException e) {
                    Assertions.fail("Counter should have been reset by the successful login; " +
                            "AccountLockedException was thrown prematurely");
                } catch (UnauthorizedException ignored) { /* expected */ }
            }
        } finally {
            clearAttempts(VALID_USER);
            disableLockout();
        }
    }

    // H8-5  Login while locked rejects immediately — even with correct password

    @Test
    @Order(5)
    void loginAlreadyLockedRejectsCorrectCredentialsToo() {
        enableLockout();
        try {
            // Lock the account
            for (int i = 0; i < LOCKOUT_THRESHOLD; i++) {
                try {
                    authenticationSystemApi.login(VALID_USER, WRONG_PWD, TEST_ISSUER);
                } catch (UnauthorizedException ignored) { /* expected */ }
            }
            // Ensure it is locked
            Assertions.assertThrows(AccountLockedException.class,
                    () -> authenticationSystemApi.login(VALID_USER, WRONG_PWD, TEST_ISSUER));

            // Even correct credentials must be rejected while locked
            Assertions.assertThrows(AccountLockedException.class,
                    () -> authenticationSystemApi.login(VALID_USER, VALID_PWD, TEST_ISSUER),
                    "A locked account must be rejected even when correct credentials are supplied");
        } finally {
            clearAttempts(VALID_USER);
            disableLockout();
        }
    }

    // H8-6  AccountLockedException extends UnauthorizedException (HTTP 401 contract)

    @Test
    @Order(6)
    void accountLockedExceptionExtendsUnauthorizedException() {
        AccountLockedException ex = new AccountLockedException(12_000L);
        Assertions.assertInstanceOf(UnauthorizedException.class, ex,
                "AccountLockedException must extend UnauthorizedException so it maps to HTTP 401");
        Assertions.assertEquals(12_000L, ex.getRemainingLockMillis(),
                "getRemainingLockMillis() must return the value passed to the constructor");
        Assertions.assertNotNull(ex.getMessage(),
                "Exception message must not be null");
    }
}
