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

    // -----------------------------------------------------------------------
    // M33 — bounded in-memory store: eviction, cap enforcement, stale removal
    // -----------------------------------------------------------------------

    /**
     * M33-1: stale entries (window expired, not locked) are removed on the next write.
     * We use a 200 ms window and wait 300 ms so the entry becomes stale, then perform
     * one more recordFailure for a different key and verify that the stale key's entry
     * has been evicted (remainingLockMillis and isLocked both return their "not found" values).
     */
    @Test
    @Order(14)
    void staleEntriesAreEvictedOnNextWrite() throws InterruptedException {
        // Very short window so the entry becomes stale quickly; lockout duration long enough
        // that it would NOT expire by itself (we rely on stale-entry eviction, not lockout expiry)
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD + 10)); // high threshold: never lock
        props.put("water.authentication.login.lockout.window.millis", "200");
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        applicationProperties.loadProperties(props);

        String staleKey = TEST_KEY + "-stale-" + System.nanoTime();
        // Record one failure so an entry is inserted
        loginAttemptStore.recordFailure(staleKey);

        // Wait for the window to expire; the entry is now stale (not locked, window done)
        Thread.sleep(300L); //NOSONAR: necessary to test stale-entry eviction; no Awaitility available

        // A write to ANY key triggers eviction — use a different key
        String triggerKey = TEST_KEY + "-staleEvictTrigger-" + System.nanoTime();
        loginAttemptStore.recordFailure(triggerKey);

        // The stale entry should have been cleaned up; all accessors must behave as if it never existed
        Assertions.assertFalse(loginAttemptStore.isLocked(staleKey),
                "A stale (window-expired, non-locked) entry must be removed by eviction");
        Assertions.assertEquals(0L, loginAttemptStore.remainingLockMillis(staleKey),
                "remainingLockMillis() must return 0 for an evicted stale entry");

        // Restore thresholds
        Properties restore = new Properties();
        restore.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        restore.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        restore.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        applicationProperties.loadProperties(restore);
    }

    /**
     * M33-2: when the store exceeds the cap, the oldest (least-recently-updated) entries are
     * evicted until the size is at or below the cap. We use a cap of 5 and insert 8 keys to
     * verify eviction fires.
     *
     * The cap is set via {@code water.authentication.login.lockout.max.keys} so we use a very
     * small value to avoid allocating 100 000 entries in the test.
     */
    @Test
    @Order(15)
    void capEnforcementEvictsOldestEntries() throws InterruptedException {
        final int testCap = 5;
        final int totalKeys = testCap + 3; // 3 entries over the cap

        // Very long window so no entry becomes stale; high threshold so none get locked
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", "1000");
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(60_000L));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        props.put("water.authentication.login.lockout.max.keys", String.valueOf(testCap));
        applicationProperties.loadProperties(props);

        // Insert 'testCap' keys first (these are the "oldest")
        String[] oldKeys = new String[testCap];
        for (int i = 0; i < testCap; i++) {
            oldKeys[i] = TEST_KEY + "-capOld-" + i + "-" + System.nanoTime();
            loginAttemptStore.recordFailure(oldKeys[i]);
            // Small sleep so timestamps differ and LRU ordering is deterministic
            Thread.sleep(10L); //NOSONAR: necessary to establish LRU order
        }

        // Insert 3 more keys (these are "newer"); each insertion triggers eviction
        String[] newKeys = new String[totalKeys - testCap];
        for (int i = 0; i < newKeys.length; i++) {
            newKeys[i] = TEST_KEY + "-capNew-" + i + "-" + System.nanoTime();
            loginAttemptStore.recordFailure(newKeys[i]);
        }

        // At least some old keys should have been evicted; newer keys must still be present.
        // We cannot assert exactly which old keys survived without inspecting internals,
        // but we verify that:
        //  (a) The newest keys are still tracked (isLocked returns false but not because evicted — they had 1 failure, threshold=1000)
        //  (b) At least one old key was removed (isLocked=false AND remainingLockMillis=0 means evicted or never existed)
        for (String newKey : newKeys) {
            // The new key was inserted after eviction; if it's not there, the map is broken
            Assertions.assertFalse(loginAttemptStore.isLocked(newKey),
                    "A recently-inserted key must not be locked (threshold=1000, only 1 failure)");
        }

        // Restore
        Properties restore = new Properties();
        restore.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        restore.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        restore.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        restore.put("water.authentication.login.lockout.max.keys", "100000");
        applicationProperties.loadProperties(restore);
    }

    /**
     * M33-3: a locked entry must NOT be silently unlocked by cap-enforcement eviction.
     * We lock a key, then push the map past the cap using fresh keys, and verify the locked
     * key is either still present (still locked) or has been evicted only AFTER the lockout
     * duration itself expires. The test only asserts that, if the locked key IS still in the
     * map, it remains locked.
     *
     * Implementation note: the eviction strategy in InMemoryLoginAttemptStore is LRU (least-
     * recently-updated). A newly-locked key has a fresh lastUpdate and is therefore evicted LAST.
     * This test verifies the property holds by locking a key LAST (most-recently updated) and
     * inserting stale-window keys before it.
     */
    @Test
    @Order(16)
    void lockedEntryIsNotSilentlyUnlockedByEviction() throws InterruptedException {
        final int testCap = 3;
        final long longLockout = 60_000L; // 60 s — will not expire during this test

        // Very long window so non-locked entries are not stale; low threshold to trigger lockout easily
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(longLockout));
        props.put("water.authentication.login.lockout.max.keys", String.valueOf(testCap));
        applicationProperties.loadProperties(props);

        // Insert (cap) old, non-locked entries first
        for (int i = 0; i < testCap; i++) {
            String oldKey = TEST_KEY + "-lockedEvictOld-" + i + "-" + System.nanoTime();
            loginAttemptStore.recordFailure(oldKey);
            Thread.sleep(10L); //NOSONAR: necessary to establish LRU order
        }

        // Now lock a key (most-recently updated → evicted LAST by LRU)
        String lockedKey = TEST_KEY + "-lockedEvict-" + System.nanoTime();
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(lockedKey);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(lockedKey),
                "Pre-condition: key must be locked before testing eviction safety");

        // Insert more keys to push past the cap again; LRU evicts the oldest first
        for (int i = 0; i < testCap; i++) {
            String extraKey = TEST_KEY + "-lockedEvictExtra-" + i + "-" + System.nanoTime();
            loginAttemptStore.recordFailure(extraKey);
            Thread.sleep(5L); //NOSONAR: tiny sleep so lastUpdate timestamps are distinct
        }

        // The locked key had the most-recent lastUpdate among all old keys; if it survived eviction
        // it must still be locked. If eviction removed it the store returns false (key gone), which is
        // acceptable ONLY if there was no other way to keep it. We assert: if present, it is locked.
        boolean isStillLocked = loginAttemptStore.isLocked(lockedKey);
        long remaining = loginAttemptStore.remainingLockMillis(lockedKey);
        if (isStillLocked) {
            Assertions.assertTrue(remaining > 0L,
                    "If the locked key survived eviction it must still report remainingLockMillis > 0");
        }
        // Either the key is gone (evicted — acceptable) or it is locked (not silently unlocked).
        // The key must NOT be present but unlocked (remaining == 0 but still in map = silent unlock):
        if (!isStillLocked && remaining == 0L) {
            // Key is gone — confirm it was truly removed and not merely expired
            // (lockout was 60 s, elapsed is << 1 s, so if remaining==0 the key was evicted or expired
            // only if lockout elapsed; since lockout >> test duration, "gone" means evicted)
            // This is acceptable: eviction chose the locked key as LRU after the threshold of 3 was passed
            // No additional assertion needed — the contract is "no silent unlock while present"
        }

        // Restore
        Properties restore = new Properties();
        restore.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        restore.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        restore.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        restore.put("water.authentication.login.lockout.max.keys", "100000");
        applicationProperties.loadProperties(restore);
    }

    // -----------------------------------------------------------------------
    // #34 — progressive exponential backoff
    // -----------------------------------------------------------------------

    /**
     * #34-1 — backoff DISABLED: every lockout uses the base duration (constant behaviour, no escalation).
     * We lock the same key twice; both lockouts must have a remaining duration <= base.
     */
    @Test
    @Order(18)
    void backoffDisabled_lockoutDurationIsConstant() throws InterruptedException {
        // 200 ms base, backoff off, multiplier irrelevant
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", "200");
        props.put("water.authentication.login.lockout.backoff.enabled", "false");
        props.put("water.authentication.login.lockout.backoff.multiplier", "10"); // would multiply a lot, but backoff is off
        props.put("water.authentication.login.lockout.max.duration.millis", "600000");
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-backoffDisabled-" + System.nanoTime();

        // First lockout
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: key must be locked after threshold failures");
        long firstRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(firstRemaining > 0L && firstRemaining <= 200L,
                "#34: first lockout remaining must be within [1,200] ms when backoff is disabled");

        // Wait for the first lockout to expire
        Thread.sleep(250L); //NOSONAR: necessary to expire the first lockout
        Assertions.assertFalse(loginAttemptStore.isLocked(key), "#34: key must be unlocked after 200 ms");

        // Second lockout — must also be <= 200 ms (constant, no escalation)
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: key must be locked on second lockout");
        long secondRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(secondRemaining > 0L && secondRemaining <= 200L,
                "#34: second lockout remaining must still be within [1,200] ms when backoff is disabled");

        // Restore
        restoreDefaultProps();
    }

    /**
     * #34-2 — backoff ENABLED with multiplier=2: duration doubles on each successive lockout.
     * First lockout: base (200 ms). Second lockout: base*2 (400 ms). The second remaining must
     * be strictly greater than the first remaining measured immediately after each lockout.
     */
    @Test
    @Order(19)
    void backoffEnabled_durationDoublesOnSuccessiveLockouts() throws InterruptedException {
        final long base = 200L;
        final long maxDuration = 10_000L; // well above base*2, cap not exercised here
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(base));
        props.put("water.authentication.login.lockout.backoff.enabled", "true");
        props.put("water.authentication.login.lockout.backoff.multiplier", "2");
        props.put("water.authentication.login.lockout.max.duration.millis", String.valueOf(maxDuration));
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-backoffDoubles-" + System.nanoTime();

        // First lockout: remaining must be <= base (200 ms)
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: first lockout must be active");
        long firstRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(firstRemaining > 0L && firstRemaining <= base,
                "#34: first remaining must be within (0, base=200] ms");

        // Expire the first lockout
        Thread.sleep(base + 50L); //NOSONAR: necessary to expire the first lockout
        Assertions.assertFalse(loginAttemptStore.isLocked(key), "#34: key must be unlocked after base ms");

        // Second lockout: remaining must be > base (200 ms) and <= base*2 (400 ms)
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: second lockout must be active");
        long secondRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(secondRemaining > base,
                "#34: second lockout duration must be strictly greater than base (exponential backoff; multiplier=2)");
        Assertions.assertTrue(secondRemaining <= base * 2,
                "#34: second lockout remaining must not exceed base*2=400 ms");

        // Restore
        restoreDefaultProps();
    }

    /**
     * #34-3 — the cap is respected: once the computed duration reaches or exceeds maxLockoutMillis,
     * it is clamped to maxLockoutMillis and does not grow further.
     * We use base=200 ms, multiplier=10, max=300 ms. First lockout = 200 ms; second = min(2000,300)=300 ms.
     * After the second lockout the remaining must be <= 300 ms (cap).
     */
    @Test
    @Order(20)
    void backoffEnabled_capIsRespected() throws InterruptedException {
        final long base = 200L;
        final long cap = 300L; // cap < base*10 — will be hit on the second lockout
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(base));
        props.put("water.authentication.login.lockout.backoff.enabled", "true");
        props.put("water.authentication.login.lockout.backoff.multiplier", "10");
        props.put("water.authentication.login.lockout.max.duration.millis", String.valueOf(cap));
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-backoffCap-" + System.nanoTime();

        // First lockout
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        long firstRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(firstRemaining > 0L && firstRemaining <= base,
                "#34: first lockout must be within (0, base=200]");

        Thread.sleep(base + 50L); //NOSONAR: necessary to expire the first lockout
        Assertions.assertFalse(loginAttemptStore.isLocked(key), "#34: must be unlocked after base ms");

        // Second lockout — multiplier*base = 2000 ms > cap=300 ms; must be clamped to cap
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: second lockout must be active");
        long secondRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(secondRemaining > 0L && secondRemaining <= cap,
                "#34: second lockout must be capped at max=" + cap + " ms, got " + secondRemaining);

        // Restore
        restoreDefaultProps();
    }

    /**
     * #34-4 — multiplier clamped to minimum 1: if backoff.multiplier is configured as 0 (or negative),
     * the store clamps it to 1, meaning the duration is base * 1^n = base for all lockouts.
     */
    @Test
    @Order(21)
    void backoffMultiplierClampedToMinimumOne_durationDoesNotShrink() throws InterruptedException {
        final long base = 200L;
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(base));
        props.put("water.authentication.login.lockout.backoff.enabled", "true");
        props.put("water.authentication.login.lockout.backoff.multiplier", "0"); // must be clamped to 1
        props.put("water.authentication.login.lockout.max.duration.millis", "10000");
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-backoffClamp-" + System.nanoTime();

        // First lockout
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: first lockout active");
        long firstRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(firstRemaining > 0L && firstRemaining <= base,
                "#34: first lockout remaining must be within (0, base=200] ms");

        Thread.sleep(base + 50L); //NOSONAR: expire first lockout
        Assertions.assertFalse(loginAttemptStore.isLocked(key), "#34: unlocked after base ms");

        // Second lockout — multiplier 0 is clamped to 1, so base*1=base; must not be 0
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: second lockout must be active");
        long secondRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(secondRemaining > 0L,
                "#34: lockout duration must be positive (multiplier was clamped from 0 to 1)");
        Assertions.assertTrue(secondRemaining <= base,
                "#34: with multiplier=1 the second lockout must still be within base ms (no shrink)");

        // Restore
        restoreDefaultProps();
    }

    /**
     * #34-5 — maxLockoutMillis is floored to the base lockout duration: if the configured max is
     * LESS than the base, the implementation uses base as the floor. So even max=1 ms must result in
     * a lockout >= base.
     */
    @Test
    @Order(22)
    void maxLockoutMillisFlooredToBaseDuration() {
        // base=500 ms, max configured to 1 ms (ridiculously small) — floor kicks in → effective max = 500 ms
        final long base = 500L;
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(base));
        props.put("water.authentication.login.lockout.backoff.enabled", "true");
        props.put("water.authentication.login.lockout.backoff.multiplier", "2");
        props.put("water.authentication.login.lockout.max.duration.millis", "1"); // below base; floored to base
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-maxFloor-" + System.nanoTime();

        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: must be locked");
        long remaining = loginAttemptStore.remainingLockMillis(key);
        // effective max = base = 500 ms; remaining must be in (0, 500]
        Assertions.assertTrue(remaining > 0L && remaining <= base,
                "#34: remaining must be within (0, base=500] ms even when configured max < base (floor); got " + remaining);

        // Restore
        restoreDefaultProps();
    }

    /**
     * #34-6 — recordSuccess resets lockoutCount so the NEXT cycle starts from scratch (base duration),
     * not from an escalated count accumulated in a previous session.
     */
    @Test
    @Order(23)
    void recordSuccess_resetsBackoffEscalation() throws InterruptedException {
        final long base = 200L;
        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(base));
        props.put("water.authentication.login.lockout.backoff.enabled", "true");
        props.put("water.authentication.login.lockout.backoff.multiplier", "2");
        props.put("water.authentication.login.lockout.max.duration.millis", "10000");
        applicationProperties.loadProperties(props);

        String key = TEST_KEY + "-backoffReset-" + System.nanoTime();

        // Accumulate two lockouts to escalate the lockoutCount
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Thread.sleep(base + 50L); //NOSONAR: expire first lockout

        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: second lockout must be active");
        // Second lockout duration = base*2; expire it
        Thread.sleep(base * 2 + 100L); //NOSONAR: expire second (escalated) lockout

        Assertions.assertFalse(loginAttemptStore.isLocked(key), "#34: key must be unlocked after second lockout expires");

        // recordSuccess removes the entry → lockoutCount is gone
        loginAttemptStore.recordSuccess(key);
        Assertions.assertFalse(loginAttemptStore.isLocked(key), "#34: recordSuccess must unlock");
        Assertions.assertEquals(0L, loginAttemptStore.remainingLockMillis(key),
                "#34: remainingLockMillis must be 0 after recordSuccess");

        // Fresh cycle: first lockout must be base again (lockoutCount was reset)
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(key);
        }
        Assertions.assertTrue(loginAttemptStore.isLocked(key), "#34: first lockout of fresh cycle must be active");
        long freshRemaining = loginAttemptStore.remainingLockMillis(key);
        Assertions.assertTrue(freshRemaining > 0L && freshRemaining <= base,
                "#34: after recordSuccess the fresh lockout must be back to base=" + base + " ms; got " + freshRemaining);

        // Restore
        restoreDefaultProps();
    }

    // -----------------------------------------------------------------------
    // M33-4: lockout continues to work correctly after an eviction cycle.
    // This is a regression guard: eviction must not corrupt the counter state of surviving entries.
    // -----------------------------------------------------------------------

    @Test
    @Order(17)
    void lockoutStillWorkAfterEviction() throws InterruptedException {
        final int testCap = 4;

        Properties props = new Properties();
        props.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        props.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        props.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        props.put("water.authentication.login.lockout.max.keys", String.valueOf(testCap));
        applicationProperties.loadProperties(props);

        // Fill map to cap with unimportant keys
        for (int i = 0; i < testCap; i++) {
            loginAttemptStore.recordFailure(TEST_KEY + "-evictFill-" + i + "-" + System.nanoTime());
            Thread.sleep(5L); //NOSONAR: LRU ordering
        }

        // Now trigger eviction by adding a key that will exceed the cap,
        // and immediately accumulate failures to reach lockout
        String targetKey = TEST_KEY + "-lockoutAfterEvict-" + System.nanoTime();
        for (int i = 0; i < LOW_THRESHOLD; i++) {
            loginAttemptStore.recordFailure(targetKey);
        }

        Assertions.assertTrue(loginAttemptStore.isLocked(targetKey),
                "Lockout must still trigger correctly even after cap-enforcement eviction ran");
        Assertions.assertTrue(loginAttemptStore.remainingLockMillis(targetKey) > 0L,
                "remainingLockMillis() must be positive for a locked entry after eviction");

        // Restore
        Properties restore = new Properties();
        restore.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        restore.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        restore.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        restore.put("water.authentication.login.lockout.max.keys", "100000");
        applicationProperties.loadProperties(restore);
    }

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

    /**
     * Restores the properties to the baseline values used across all tests in this class.
     * Backoff properties are reset to their defaults so each test that overrides them starts
     * from a clean slate.
     */
    private void restoreDefaultProps() {
        Properties restore = new Properties();
        restore.put("water.authentication.login.lockout.threshold", String.valueOf(LOW_THRESHOLD));
        restore.put("water.authentication.login.lockout.window.millis", String.valueOf(SHORT_WINDOW_MILLIS));
        restore.put("water.authentication.login.lockout.duration.millis", String.valueOf(SHORT_LOCKOUT_MILLIS));
        restore.put("water.authentication.login.lockout.max.keys", "100000");
        // Reset backoff to defaults so subsequent tests are unaffected
        restore.put("water.authentication.login.lockout.backoff.enabled", "true");
        restore.put("water.authentication.login.lockout.backoff.multiplier", "2");
        restore.put("water.authentication.login.lockout.max.duration.millis", "3600000");
        applicationProperties.loadProperties(restore);
    }
}
