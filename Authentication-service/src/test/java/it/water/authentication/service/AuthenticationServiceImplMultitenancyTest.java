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

import it.water.authentication.api.AuthenticationSystemApi;
import it.water.core.api.bundle.Runtime;
import it.water.core.api.permission.SecurityContext;
import it.water.core.api.registry.ComponentRegistry;
import it.water.core.api.security.Authenticable;
import it.water.core.permission.exceptions.UnauthorizedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Plain Mockito unit tests for the multitenancy additions on {@link AuthenticationServiceImpl}
 * (Api layer): the {@code login(username, password, companyId, clientIp)} pass-through overload
 * and the new {@code impersonate(targetUsername, companyId)} method, which resolves the caller
 * from the current {@link SecurityContext} and requires the caller to be logged in.
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationServiceImplMultitenancyTest {

    @Mock
    private AuthenticationSystemApi systemService;

    @Mock
    private ComponentRegistry componentRegistry;

    @Mock
    private Runtime runtime;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authenticable authenticable;

    private AuthenticationServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new AuthenticationServiceImpl();
        service.setSystemService(systemService);
        service.setComponentRegistry(componentRegistry);
        service.setRuntime(runtime);
    }

    @Test
    void login_withCompanyIdAndClientIp_delegatesToSystemServiceFiveArgOverload() {
        when(systemService.login("user1", "pwd1", null, 42L, "10.0.0.1")).thenReturn(authenticable);

        Authenticable result = service.login("user1", "pwd1", 42L, "10.0.0.1");

        Assertions.assertSame(authenticable, result);
        verify(systemService).login("user1", "pwd1", null, 42L, "10.0.0.1");
    }

    @Test
    void impersonate_callerNotLoggedIn_throwsUnauthorizedAndNeverCallsSystemService() {
        when(runtime.getSecurityContext()).thenReturn(securityContext);
        when(securityContext.isLoggedIn()).thenReturn(false);

        Assertions.assertThrows(UnauthorizedException.class, () -> service.impersonate("target1", 5L));

        verifyNoInteractions(systemService);
    }

    @Test
    void impersonate_nullSecurityContext_throwsUnauthorized() {
        when(runtime.getSecurityContext()).thenReturn(null);

        Assertions.assertThrows(UnauthorizedException.class, () -> service.impersonate("target1", 5L));

        verifyNoInteractions(systemService);
    }

    @Test
    void impersonate_nullRuntime_throwsUnauthorized() {
        service.setRuntime(null);

        Assertions.assertThrows(UnauthorizedException.class, () -> service.impersonate("target1", 5L));

        verifyNoInteractions(systemService);
    }

    @Test
    void impersonate_loggedInWithBlankUsername_throwsUnauthorized() {
        when(runtime.getSecurityContext()).thenReturn(securityContext);
        when(securityContext.isLoggedIn()).thenReturn(true);
        when(securityContext.getLoggedUsername()).thenReturn("   ");

        Assertions.assertThrows(UnauthorizedException.class, () -> service.impersonate("target1", 5L));

        verifyNoInteractions(systemService);
    }

    @Test
    void impersonate_loggedIn_resolvesCallerFromSecurityContext_delegatesToSystemService() {
        when(runtime.getSecurityContext()).thenReturn(securityContext);
        when(securityContext.isLoggedIn()).thenReturn(true);
        when(securityContext.getLoggedUsername()).thenReturn("callerUser");
        when(systemService.impersonate("target1", "callerUser", 55L)).thenReturn(authenticable);

        Authenticable result = service.impersonate("target1", 55L);

        Assertions.assertSame(authenticable, result);
        verify(systemService).impersonate("target1", "callerUser", 55L);
    }
}
