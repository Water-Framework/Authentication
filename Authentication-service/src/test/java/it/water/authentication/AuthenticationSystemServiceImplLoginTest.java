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
import it.water.authentication.api.options.AuthenticationOption;
import it.water.authentication.service.AuthenticationConstants;
import it.water.authentication.service.AuthenticationSystemServiceImpl;
import it.water.authentication.service.execption.AccountLockedException;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.api.registry.ComponentRegistry;
import it.water.core.api.security.Authenticable;
import it.water.core.api.security.AuthenticationProvider;
import it.water.core.permission.exceptions.UnauthorizedException;
import it.water.service.rest.api.security.jwt.JwtTokenService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Set;

/**
 * Mockito unit tests for {@link AuthenticationSystemServiceImpl} — focused on the new login
 * overloads introduced by fix #34 (IP-scoped lockout key + delegation chain).
 *
 * <p>These tests use Mockito only (no WaterTestExtension / no Spring context) so lockout is NOT
 * disabled by testMode. This means we can exercise the full lockout path, including
 * {@link AccountLockedException}, by directly configuring the {@link LoginAttemptStore} mock.
 *
 * <p>Coverage targets:
 * <ul>
 *   <li>{@code login(u,p)} → delegates to default issuer (retro-compatibility).</li>
 *   <li>{@code login(u,p,issuer)} → delegates to 4-arg overload with null IP.</li>
 *   <li>{@code login(u,p,issuer,ip)} — happy path: provider returns Authenticable.</li>
 *   <li>{@code login(u,p,issuer,ip)} — locked key: throws AccountLockedException.</li>
 *   <li>{@code login(u,p,issuer,ip)} — null/blank IP: key uses "unknown" as IP segment.</li>
 *   <li>{@code login(u,p,issuer,ip)} — provider returns null: recordFailure called, UnauthorizedException thrown.</li>
 *   <li>{@code login(u,p,issuer,ip)} — provider throws RuntimeException: recordFailure called, exception propagated.</li>
 *   <li>{@code login(u,p,issuer,ip)} — no provider for issuer: UnauthorizedException thrown.</li>
 *   <li>{@code login(u,p,issuer,ip)} — different clientIps produce different lockout keys (no cross-contamination).</li>
 *   <li>{@code login(u,p,null,ip)} — null issuer filter falls back to default issuer.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthenticationSystemServiceImplLoginTest {

    private static final String DEFAULT_ISSUER = "water";
    private static final String USERNAME = "testUser";
    private static final String PASSWORD = "testPass";
    private static final String CLIENT_IP = "1.2.3.4";

    @Mock
    private ComponentRegistry componentRegistry;

    @Mock
    private AuthenticationOption authenticationOption;

    @Mock
    private JwtTokenService jwtTokenService;

    @Mock
    private LoginAttemptStore loginAttemptStore;

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private AuthenticationProvider authenticationProvider;

    @Mock
    private Authenticable authenticable;

    @InjectMocks
    private AuthenticationSystemServiceImpl sut;

    /**
     * Common setup: testMode=false so lockout enforcement is active in all tests.
     * Individual tests may override applicationProperties behaviour via additional stubs.
     */
    @BeforeEach
    void setUp() {
        // testMode=false → lockout is enabled → security controls are exercised
        Mockito.lenient().when(applicationProperties.getProperty(AuthenticationConstants.TEST_MODE))
                .thenReturn("false");
        // Default issuer is resolved only when the issuer argument is null, so this stub is lenient:
        // tests that pass an explicit issuer never trigger it.
        Mockito.lenient().when(authenticationOption.getIssuerName()).thenReturn(DEFAULT_ISSUER);
    }

    // -----------------------------------------------------------------------
    // Delegation chain — retro-compatibility
    // -----------------------------------------------------------------------

    /**
     * login(u,p) must delegate to login(u,p,defaultIssuer,null) and return the Authenticable
     * from the provider, invoking recordSuccess on the lockout store.
     */
    @Test
    @Order(1)
    void login_twoArg_delegatesToDefaultIssuerAndReturnsAuthenticable() {
        Mockito.when(loginAttemptStore.isLocked(Mockito.anyString())).thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        Authenticable result = sut.login(USERNAME, PASSWORD);

        Assertions.assertNotNull(result, "login(u,p) must return the Authenticable from the provider");
        Mockito.verify(loginAttemptStore).recordSuccess(Mockito.anyString());
    }

    /**
     * login(u,p,issuer) must delegate to the 4-arg overload (null IP) and succeed.
     */
    @Test
    @Order(2)
    void login_threeArg_delegatesWithNullIp_returnsAuthenticable() {
        Mockito.when(loginAttemptStore.isLocked(Mockito.anyString())).thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        Authenticable result = sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER);

        Assertions.assertNotNull(result, "login(u,p,issuer) must return the Authenticable");
        // IP was null → key must contain "unknown"
        Mockito.verify(loginAttemptStore).isLocked(Mockito.argThat(k -> k.contains(":unknown:")));
    }

    // -----------------------------------------------------------------------
    // Happy path — 4-arg overload with explicit clientIp
    // -----------------------------------------------------------------------

    /**
     * login(u,p,issuer,ip) — happy path: not locked, provider returns Authenticable, success
     * recorded on the store.
     */
    @Test
    @Order(3)
    void login_fourArg_happyPath_returnsAuthenticableAndRecordsSuccess() {
        Mockito.when(loginAttemptStore.isLocked(DEFAULT_ISSUER + ":" + CLIENT_IP + ":" + USERNAME))
                .thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        Authenticable result = sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, CLIENT_IP);

        Assertions.assertSame(authenticable, result,
                "#34 happy path: the Authenticable returned by the provider must be returned");
        String expectedKey = DEFAULT_ISSUER + ":" + CLIENT_IP + ":" + USERNAME;
        Mockito.verify(loginAttemptStore).recordSuccess(expectedKey);
        Mockito.verify(loginAttemptStore, Mockito.never()).recordFailure(Mockito.anyString());
    }

    // -----------------------------------------------------------------------
    // Lockout path — AccountLockedException
    // -----------------------------------------------------------------------

    /**
     * When the lockout key is locked, login must throw AccountLockedException immediately, without
     * reaching the authentication provider.
     */
    @Test
    @Order(4)
    void login_fourArg_keyLocked_throwsAccountLockedException() {
        String expectedKey = DEFAULT_ISSUER + ":" + CLIENT_IP + ":" + USERNAME;
        Mockito.when(loginAttemptStore.isLocked(expectedKey)).thenReturn(true);
        Mockito.when(loginAttemptStore.remainingLockMillis(expectedKey)).thenReturn(30_000L);

        AccountLockedException ex = Assertions.assertThrows(AccountLockedException.class,
                () -> sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, CLIENT_IP),
                "#34: locked key must cause AccountLockedException");
        Assertions.assertTrue(ex.getRemainingLockMillis() > 0L,
                "#34: AccountLockedException must carry a positive remaining lock duration");
        // Provider must never be consulted
        Mockito.verify(componentRegistry, Mockito.never())
                .findComponents(Mockito.any(), Mockito.any());
    }

    // -----------------------------------------------------------------------
    // clientIp null / blank → "unknown" segment
    // -----------------------------------------------------------------------

    /**
     * When clientIp is null, the key must use "unknown" as the IP segment so behaviour degrades
     * gracefully rather than NPE-ing.
     */
    @Test
    @Order(5)
    void login_fourArg_nullClientIp_usesUnknownSegment() {
        Mockito.when(loginAttemptStore.isLocked(DEFAULT_ISSUER + ":unknown:" + USERNAME))
                .thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        Authenticable result = sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, null);

        Assertions.assertNotNull(result, "#34: null clientIp must not prevent successful login");
        String expectedKey = DEFAULT_ISSUER + ":unknown:" + USERNAME;
        Mockito.verify(loginAttemptStore).isLocked(expectedKey);
        Mockito.verify(loginAttemptStore).recordSuccess(expectedKey);
    }

    /**
     * When clientIp is blank (only whitespace), the key must also use "unknown".
     */
    @Test
    @Order(6)
    void login_fourArg_blankClientIp_usesUnknownSegment() {
        Mockito.when(loginAttemptStore.isLocked(DEFAULT_ISSUER + ":unknown:" + USERNAME))
                .thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        Authenticable result = sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, "   ");

        Assertions.assertNotNull(result, "#34: blank clientIp must not prevent successful login");
        Mockito.verify(loginAttemptStore).isLocked(DEFAULT_ISSUER + ":unknown:" + USERNAME);
    }

    // -----------------------------------------------------------------------
    // Provider returns null — failure, UnauthorizedException
    // -----------------------------------------------------------------------

    /**
     * When the provider returns null (signals failure without throwing), recordFailure must be
     * called and UnauthorizedException must be thrown.
     */
    @Test
    @Order(7)
    void login_fourArg_providerReturnsNull_recordsFailureAndThrowsUnauthorized() {
        String key = DEFAULT_ISSUER + ":" + CLIENT_IP + ":" + USERNAME;
        Mockito.when(loginAttemptStore.isLocked(key)).thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(null);

        Assertions.assertThrows(UnauthorizedException.class,
                () -> sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, CLIENT_IP),
                "Provider returning null must cause UnauthorizedException");

        Mockito.verify(loginAttemptStore).recordFailure(key);
        Mockito.verify(loginAttemptStore, Mockito.never()).recordSuccess(Mockito.anyString());
    }

    // -----------------------------------------------------------------------
    // Provider throws RuntimeException — failure, exception propagated
    // -----------------------------------------------------------------------

    /**
     * When the provider throws a RuntimeException, recordFailure must be called and the exception
     * must propagate unmodified to the caller.
     */
    @Test
    @Order(8)
    void login_fourArg_providerThrowsRuntimeException_recordsFailureAndPropagatesException() {
        String key = DEFAULT_ISSUER + ":" + CLIENT_IP + ":" + USERNAME;
        RuntimeException providerError = new RuntimeException("DB connection failed");

        Mockito.when(loginAttemptStore.isLocked(key)).thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenThrow(providerError);

        RuntimeException thrown = Assertions.assertThrows(RuntimeException.class,
                () -> sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, CLIENT_IP),
                "Provider exception must propagate");
        Assertions.assertSame(providerError, thrown, "The same RuntimeException instance must propagate");
        Mockito.verify(loginAttemptStore).recordFailure(key);
    }

    // -----------------------------------------------------------------------
    // No provider found for issuer
    // -----------------------------------------------------------------------

    /**
     * When no AuthenticationProvider is registered for the requested issuer, login must throw
     * UnauthorizedException without touching the lockout store.
     */
    @Test
    @Order(9)
    void login_fourArg_noProviderForIssuer_throwsUnauthorizedException() {
        Mockito.when(loginAttemptStore.isLocked(Mockito.anyString())).thenReturn(false);
        // Empty provider list — no match for issuer
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of());

        Assertions.assertThrows(UnauthorizedException.class,
                () -> sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, CLIENT_IP),
                "No provider for issuer must cause UnauthorizedException");

        Mockito.verify(loginAttemptStore, Mockito.never()).recordFailure(Mockito.anyString());
        Mockito.verify(loginAttemptStore, Mockito.never()).recordSuccess(Mockito.anyString());
    }

    // -----------------------------------------------------------------------
    // Different clientIps produce different lockout keys — no cross-contamination
    // -----------------------------------------------------------------------

    /**
     * Two concurrent users with the same username but different IPs must produce independent lockout
     * keys. Locking IP A must not lock IP B.
     */
    @Test
    @Order(10)
    void login_fourArg_differentClientIps_useIndependentLockoutKeys() {
        String keyA = DEFAULT_ISSUER + ":1.1.1.1:" + USERNAME;
        String keyB = DEFAULT_ISSUER + ":2.2.2.2:" + USERNAME;

        // IP A is locked; IP B is not
        Mockito.when(loginAttemptStore.isLocked(keyA)).thenReturn(true);
        Mockito.when(loginAttemptStore.remainingLockMillis(keyA)).thenReturn(10_000L);
        Mockito.when(loginAttemptStore.isLocked(keyB)).thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        // IP A → must be rejected
        Assertions.assertThrows(AccountLockedException.class,
                () -> sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, "1.1.1.1"),
                "#34: locked IP must be rejected");

        // IP B → must succeed (different key, not locked)
        Authenticable result = sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, "2.2.2.2");
        Assertions.assertNotNull(result, "#34: different IP must not be affected by lockout on another IP");
    }

    // -----------------------------------------------------------------------
    // null authProviderFilter falls back to default issuer
    // -----------------------------------------------------------------------

    /**
     * When authProviderFilter (the issuer argument) is null, the implementation must use the
     * default issuer from AuthenticationOption.
     */
    @Test
    @Order(11)
    void login_fourArg_nullIssuerFilter_fallsBackToDefaultIssuer() {
        Mockito.when(loginAttemptStore.isLocked(Mockito.anyString())).thenReturn(false);
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        // null issuer → must fall back to DEFAULT_ISSUER
        Authenticable result = sut.login(USERNAME, PASSWORD, null, CLIENT_IP);

        Assertions.assertNotNull(result, "#34: null issuer filter must fall back to default issuer");
        // Key must include the resolved DEFAULT_ISSUER, not "null"
        Mockito.verify(loginAttemptStore).isLocked(
                Mockito.argThat(k -> k.startsWith(DEFAULT_ISSUER + ":")));
    }

    // -----------------------------------------------------------------------
    // testMode=true: lockout disabled (isLockoutEnabled returns false)
    // -----------------------------------------------------------------------

    /**
     * When testMode=true, the lockout store must never be consulted or updated — the store is
     * bypassed entirely. This mirrors the behaviour in the WaterTestExtension-based integration tests
     * (AuthenticationApiTest), here confirmed at the unit level.
     */
    @Test
    @Order(12)
    void login_fourArg_testModeEnabled_lockoutStoreNotConsulted() {
        // Override: testMode=true
        Mockito.when(applicationProperties.getProperty(AuthenticationConstants.TEST_MODE))
                .thenReturn("true");
        Mockito.when(componentRegistry.findComponents(AuthenticationProvider.class, null))
                .thenReturn(List.of(authenticationProvider));
        Mockito.when(authenticationProvider.issuersNames()).thenReturn(Set.of(DEFAULT_ISSUER));
        Mockito.when(authenticationProvider.login(USERNAME, PASSWORD)).thenReturn(authenticable);

        Authenticable result = sut.login(USERNAME, PASSWORD, DEFAULT_ISSUER, CLIENT_IP);

        Assertions.assertNotNull(result, "testMode=true: login must succeed without consulting the lockout store");
        Mockito.verify(loginAttemptStore, Mockito.never()).isLocked(Mockito.anyString());
        Mockito.verify(loginAttemptStore, Mockito.never()).recordFailure(Mockito.anyString());
        Mockito.verify(loginAttemptStore, Mockito.never()).recordSuccess(Mockito.anyString());
    }
}
