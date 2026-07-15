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

import it.water.core.api.bundle.ApplicationProperties;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.when;

/**
 * Plain Mockito unit tests for the multitenancy enablement flag added to
 * {@link AuthenticationOptionImpl#isMultiTenantEnabled()}. Deliberately does NOT use
 * {@code WaterTestExtension}: this class is instantiated directly and its single collaborator
 * ({@link ApplicationProperties}) is mocked, so every branch of the new method can be exercised in
 * isolation without touching the module's shared test properties singleton.
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationOptionImplMultitenancyTest {

    @Mock
    private ApplicationProperties applicationProperties;

    @Test
    void isMultiTenantEnabled_propertyAbsent_returnsFalse() {
        AuthenticationOptionImpl option = new AuthenticationOptionImpl();
        option.setApplicationProperties(applicationProperties);
        when(applicationProperties.getProperty(AuthenticationConstants.MULTITENANT_ENABLED)).thenReturn(null);

        Assertions.assertFalse(option.isMultiTenantEnabled(),
                "with no property configured, multitenancy must default to disabled (single-tenant/legacy)");
    }

    @Test
    void isMultiTenantEnabled_propertyTrue_returnsTrue() {
        AuthenticationOptionImpl option = new AuthenticationOptionImpl();
        option.setApplicationProperties(applicationProperties);
        when(applicationProperties.getProperty(AuthenticationConstants.MULTITENANT_ENABLED)).thenReturn("true");

        Assertions.assertTrue(option.isMultiTenantEnabled());
    }

    @Test
    void isMultiTenantEnabled_propertyFalseString_returnsFalse() {
        AuthenticationOptionImpl option = new AuthenticationOptionImpl();
        option.setApplicationProperties(applicationProperties);
        when(applicationProperties.getProperty(AuthenticationConstants.MULTITENANT_ENABLED)).thenReturn("false");

        Assertions.assertFalse(option.isMultiTenantEnabled());
    }

    @Test
    void isMultiTenantEnabled_nullApplicationProperties_returnsFalse() {
        AuthenticationOptionImpl option = new AuthenticationOptionImpl();
        option.setApplicationProperties(null);

        Assertions.assertFalse(option.isMultiTenantEnabled(),
                "a missing ApplicationProperties collaborator must never break the check (defaults to disabled)");
    }
}
