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

package it.water.authentication.service;

import it.water.authentication.api.LoginAttemptStore;
import it.water.authentication.api.options.AuthenticationOption;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.api.registry.ComponentRegistry;
import it.water.core.api.security.Authenticable;
import it.water.core.api.security.AuthenticationProvider;
import it.water.core.api.service.integration.CompanyIntegrationClient;
import it.water.core.permission.exceptions.UnauthorizedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Plain Mockito unit tests for the multitenancy threading added to
 * {@link AuthenticationSystemServiceImpl}: the {@code isMultiTenantEnabled()} branch inside
 * {@code login(username, password, authProviderFilter, companyId, clientIp)} (3-arg provider
 * overload vs. legacy 2-arg) and the new {@code impersonate(targetUsername, callerUsername,
 * companyId)} method.
 * <p>
 * Deliberately does NOT use {@code WaterTestExtension}/classpath scanning: {@code componentRegistry}
 * is mocked to return a hand-built {@link AuthenticationProvider} mock, so these tests never depend
 * on which real {@code AuthenticationProvider} the module's shared classpath scan happens to
 * register for the module's default issuer (avoids any User/UserCompany setup entirely).
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationSystemServiceImplMultitenancyTest {

    private static final String TEST_ISSUER = "test.mt.issuer";

    @Mock
    private ComponentRegistry componentRegistry;

    @Mock
    private AuthenticationOption authenticationOption;

    @Mock
    private LoginAttemptStore loginAttemptStore;

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private AuthenticationProvider provider;

    @Mock
    private Authenticable authenticable;

    @Mock
    private CompanyIntegrationClient companyIntegrationClient;

    private AuthenticationSystemServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new AuthenticationSystemServiceImpl();
        service.setComponentRegistry(componentRegistry);
        service.setAuthenticationOption(authenticationOption);
        service.setLoginAttemptStore(loginAttemptStore);
        service.setApplicationProperties(applicationProperties);
        //lenient: not every test in this class exercises the login() path (impersonate() never reads
        //isLockoutEnabled()/TEST_MODE), so these shared stubs must not trip strict-stubbing checks
        //test mode => lockout bypassed entirely: loginAttemptStore is never consulted below
        lenient().when(applicationProperties.getProperty(AuthenticationConstants.TEST_MODE)).thenReturn("true");
        lenient().when(provider.issuersNames()).thenReturn(Collections.singleton(TEST_ISSUER));
        lenient().when(componentRegistry.findComponents(eq(AuthenticationProvider.class), any())).thenReturn(List.of(provider));
    }

    @Test
    void login_multiTenantDisabled_invokesLegacyTwoArgProviderOverload() {
        when(authenticationOption.isMultiTenantEnabled()).thenReturn(false);
        when(provider.login("user1", "pwd1")).thenReturn(authenticable);

        Authenticable result = service.login("user1", "pwd1", TEST_ISSUER, 42L, null);

        Assertions.assertSame(authenticable, result);
        verify(provider).login("user1", "pwd1");
        verify(provider, never()).login(anyString(), anyString(), any(Long.class));
        verify(loginAttemptStore, never()).isLocked(anyString());
    }

    @Test
    void login_multiTenantEnabled_invokesThreeArgProviderOverloadWithCompanyId() {
        when(authenticationOption.isMultiTenantEnabled()).thenReturn(true);
        when(provider.login("user1", "pwd1", 99L)).thenReturn(authenticable);

        Authenticable result = service.login("user1", "pwd1", TEST_ISSUER, 99L, null);

        Assertions.assertSame(authenticable, result);
        verify(provider).login("user1", "pwd1", 99L);
        verify(provider, never()).login(anyString(), anyString());
    }

    @Test
    void login_multiTenantEnabled_noCompanyRequested_stillUsesThreeArgOverloadWithNullCompany() {
        when(authenticationOption.isMultiTenantEnabled()).thenReturn(true);
        when(provider.login("user1", "pwd1", null)).thenReturn(authenticable);

        Authenticable result = service.login("user1", "pwd1", TEST_ISSUER, null, null);

        Assertions.assertSame(authenticable, result);
        verify(provider).login("user1", "pwd1", null);
    }

    @Test
    void loginForVirtualHost_resolvesCompanyBeforeAuthenticating() {
        when(authenticationOption.isMultiTenantEnabled()).thenReturn(true);
        when(componentRegistry.findComponent(CompanyIntegrationClient.class, null))
                .thenReturn(companyIntegrationClient);
        when(companyIntegrationClient.findCompanyIdByVirtualHost("tenant.example.test")).thenReturn(77L);
        when(provider.login("user1", "pwd1", 77L)).thenReturn(authenticable);

        Authenticable result = service.loginForVirtualHost(
                "user1", "pwd1", TEST_ISSUER, "tenant.example.test", "127.0.0.1");

        Assertions.assertSame(authenticable, result);
        verify(companyIntegrationClient).findCompanyIdByVirtualHost("tenant.example.test");
        verify(provider).login("user1", "pwd1", 77L);
    }

    @Test
    void loginForVirtualHost_allowsNonScopedAdminWhenNoTenantExistsYet() {
        when(authenticationOption.isMultiTenantEnabled()).thenReturn(true);
        when(componentRegistry.findComponent(CompanyIntegrationClient.class, null))
                .thenReturn(companyIntegrationClient);
        when(companyIntegrationClient.findCompanyIdByVirtualHost("unknown.example.test")).thenReturn(null);
        when(provider.login("admin", "pwd", null)).thenReturn(authenticable);
        when(authenticable.isAdmin()).thenReturn(true);

        Authenticable result = service.loginForVirtualHost(
                "admin", "pwd", TEST_ISSUER, "unknown.example.test", "127.0.0.1");

        Assertions.assertSame(authenticable, result);
        verify(provider).login("admin", "pwd", null);
    }

    @Test
    void loginForVirtualHost_rejectsTenantUserWhenHostIsUnknown() {
        when(authenticationOption.isMultiTenantEnabled()).thenReturn(true);
        when(componentRegistry.findComponent(CompanyIntegrationClient.class, null))
                .thenReturn(companyIntegrationClient);
        when(companyIntegrationClient.findCompanyIdByVirtualHost("unknown.example.test")).thenReturn(null);
        when(provider.login("user1", "pwd1", null)).thenReturn(authenticable);
        when(authenticable.isAdmin()).thenReturn(false);

        Assertions.assertThrows(UnauthorizedException.class, () ->
                service.loginForVirtualHost(
                        "user1", "pwd1", TEST_ISSUER, "unknown.example.test", "127.0.0.1"));

        verify(provider).login("user1", "pwd1", null);
    }

    @Test
    void impersonate_delegatesToResolvedProviderForDefaultIssuer() {
        when(authenticationOption.getIssuerName()).thenReturn(TEST_ISSUER);
        when(provider.impersonate("target1", "caller1", 7L)).thenReturn(authenticable);

        Authenticable result = service.impersonate("target1", "caller1", 7L);

        Assertions.assertSame(authenticable, result);
        verify(provider).impersonate("target1", "caller1", 7L);
    }

    @Test
    void impersonate_noProviderForDefaultIssuer_throwsUnauthorized() {
        when(authenticationOption.getIssuerName()).thenReturn("unresolvable-issuer");
        AuthenticationProvider otherProvider = mock(AuthenticationProvider.class);
        when(otherProvider.issuersNames()).thenReturn(Collections.singleton(TEST_ISSUER));
        when(componentRegistry.findComponents(eq(AuthenticationProvider.class), any())).thenReturn(List.of(otherProvider));

        Assertions.assertThrows(UnauthorizedException.class,
                () -> service.impersonate("target1", "caller1", null));
        verify(otherProvider, never()).impersonate(anyString(), anyString(), any());
    }
}
