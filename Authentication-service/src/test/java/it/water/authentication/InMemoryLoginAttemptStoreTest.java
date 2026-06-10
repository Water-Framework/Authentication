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

import it.water.authentication.api.LoginAttemptStore;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.api.service.Service;
import it.water.core.interceptors.annotations.Inject;
import it.water.core.testing.utils.junit.WaterTestExtension;
import lombok.Setter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Properties;

/**
 * Regression tests for H8 — InMemoryLoginAttemptStore.
 *
 * Tests the counter / window / lockout / reset semantics directly on the store,
 * independently of the authentication flow. This is intentional: the store has
 * no knowledge of testMode — it always tracks counters.  Lockout gating is the
 * responsibility of AuthenticationSystemServiceImpl.
 */
@ExtendWith(WaterTestExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class InMemoryLoginAttemptStoreTest implements Service {

    private static final String TEST_KEY = "water:testLockoutUser";
    private static final int LOW_THRESHOLD = 3;
    private static final long SHORT_WINDOW_MILLIS = 5000L;    // 5 seconds
    private static final long SHORT_LOCKOUT_MILLIS = 5000L;   // 5 seconds

    @Inject
    @Setter
    private LoginAttemptStore loginAttemptStore;

    @Inject
    @Setter
    private ApplicationProperties applicationProperties;

    @BeforeAll
    void configureShortThresholds() {
        // Use small values so tests do not have to wait 15 minutes
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        applicationProperties.loadProperties(props);
    }

    // Null-key guard

    @Test
    @Order(1)
    void isLockedNullKeyReturnsFalse() {
        Assertions.assertFalse(loginAttemptStore.isLocked(null),
                "isLocked(null) must return false without throwing");
    }

    @Test
    @Order(2)
    void recordFailureNullKeyDoesNotThrow() {
        Assertions.assertDoesNotThrow(() -> loginAttemptStore.recordFailure(null),
                "recordFailure(null) must silently ignore the null key");
    }

    @Test
    @Order(3)
    void recordSuccessNullKeyDoesNotThrow() {
        Assertions.assertDoesNotThrow(() -> loginAttemptStore.recordSuccess(null),
                "recordSuccess(null) must silently ignore the null key");
    }

    @Test
    @Order(4)
    void remainingLockMillisNullKeyReturnsZero() {
        Assertions.assertEquals(0L, loginAttemptStore.remainingLockMillis(null),
                "remainingLockMillis(null) must return 0");
    }

    // Happy path: not locked before threshold

    @Test
    @Order(5)
    void isLockedBelowThresholdReturnsFalse() {
        String key = TEST_KEY + "-belowThreshold";
        // Record (threshold - 1) failures — must NOT trigger lockout
        for (int i = 0; i < LOW_THRESHOLD - 1; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertFalse(loginAttemptStore.isLocked(key),
                "Key must NOT be locked before reaching the failure threshold");
    }

    // Lockout triggered at threshold

    @Test
    @Order(6)
    void recordFailureAtThresholdTriggersLockout() {
        String key = TEST_KEY + "-atThreshold";
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key),
                "Key must be locked after exactly <threshold> consecutive failures");
    }

    @Test
    @Order(7)
    void remainingLockMillisLockedKeyReturnsPositiveValue() {
        String key = TEST_KEY + "-remainingMillis";
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        long remaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(remaining > 0L,
                "remainingLockMillis() must be positive for a locked key");
        Assertions.assertTrue(remaining <= SHORT_LOCKOUT_MILLIS,
                "remainingLockMillis() must not exceed the configured lockout duration");
    }

    // recordSuccess resets the counter

    @Test
    @Order(8)
    void recordSuccessResetsLockout() {
        String key = TEST_KEY + "-resetOnSuccess";
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key),
                "Pre-condition: key must be locked after threshold failures");

        loginAttemptStore.recordSuccess(key);

        Assertions.assertFalse(loginAttemptStore.isLocked(key),
                "recordSuccess() must clear the lockout");
        Assertions.assertEquals(0L, loginAttemptStore.remainingLockMillis(key),
                "remainingLockMillis() must return 0 after recordSuccess()");
    }

    @Test
    @Order(9)
    void recordSuccessBeforeThresholdResetsCounterSoNextCycleNeedsFullThreshold() {
        String key = TEST_KEY + "-successBeforeThreshold";
        // Accumulate some (but not all) failures then succeed
        for (int i = 0; i < LOW_THRESHOLD - 1; i++) {
            loginAttemptStore.recordFailure(key);
        }
        loginAttemptStore.recordSuccess(key);

        // Now one more failure alone must NOT lock
        loginAttemptStore.recordFailure(key);
        Assertions.assertFalse(loginAttemptStore.isLocked(key),
                "After a success, a single failure must not lock (counter was reset)");
    }

    // Window expiry: failures outside the window must not count

    @Test
    @Order(10)
    void recordFailureWindowExpiredResetsCounter() throws InterruptedException {
        // Use a very short window for this specific sub-test
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", "200");   // 200 ms
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-windowExpiry";
        // Record (threshold - 1) failures inside the window
        for (int i = 0; i < LOW_THRESHOLD - 1; i++) {
            loginAttemptStore.recordFailure(key);
        }

        // Wait for the window to expire
        Thread.sleep(300L); //NOSONAR: necessary to test time-window expiry; no Awaitility available

        // One more failure after window reset should NOT cause lockout
        // (window restart, failures = 1, below threshold)
        loginAttemptStore.recordFailure(key);
        Assertions.assertFalse(loginAttemptStore.isLocked(key),
                "After the window expires, the failure counter must restart; " +
                "a single post-expiry failure must not lock");

        // Restore original thresholds
        Properties restore = new Properties();
        restore.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        restore.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        restore.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        applicationProperties.loadProperties(restore);
    }

    // remainingLockMillis on an unknown key returns 0

    @Test
    @Order(11)
    void remainingLockMillisUnknownKeyReturnsZero() {
        Assertions.assertEquals(0L,
                loginAttemptStore.remainingLockMillis(TEST_KEY + "-unknown-" + System.nanoTime()),
                "remainingLockMillis() must return 0 for a key that has never had a failure");
    }

    // isLocked on an unknown key returns false

    @Test
    @Order(12)
    void isLockedUnknownKeyReturnsFalse() {
        Assertions.assertFalse(
                loginAttemptStore.isLocked(TEST_KEY + "-unknown-" + System.nanoTime()),
                "isLocked() must return false for a key that has never been seen");
    }

    // Lockout duration expiry

    @Test
    @Order(13)
    void isLockedAfterLockoutDurationExpiresReturnsFalse() throws InterruptedException {
        // Configure a very short lockout duration so we don't have to wait 15 minutes
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", "200");   // 200 ms
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-lockoutExpiry";
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key),
                "Pre-condition: key must be locked");

        // Wait for lockout to expire
        Thread.sleep(300L); //NOSONAR: necessary to test lockout-duration expiry; no Awaitility available

        Assertions.assertFalse(loginAttemptStore.isLocked(key),
                "isLocked() must return false after the lockout duration has elapsed");
        Assertions.assertEquals(0L, loginAttemptStore.remainingLockMillis(key),
                "remainingLockMillis() must return 0 after lockout duration has elapsed");

        // Restore
        Properties restore = new Properties();
        restore.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        restore.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        restore.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        applicationProperties.loadProperties(restore);
    }
}
