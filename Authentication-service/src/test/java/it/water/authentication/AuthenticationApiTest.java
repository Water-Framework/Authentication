package it.water.authentication;

import it.water.authentication.api.AuthenticationApi;
import it.water.authentication.api.AuthenticationSystemApi;
import it.water.core.api.bundle.Runtime;
import it.water.core.api.registry.ComponentRegistry;
import it.water.core.api.security.Authenticable;
import it.water.core.api.service.Service;
import it.water.core.interceptors.annotations.Inject;
import it.water.core.testing.utils.junit.WaterTestExtension;
import lombok.Setter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * Generated with Water Generator.
 * Test class for Authentication Services.
 * <p>
 * Please use AuthenticationRestTestApi for ensuring format of the json response
 */
@ExtendWith(WaterTestExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthenticationApiTest implements Service {

    @Inject
    @Setter
    private ComponentRegistry componentRegistry;

    @Inject
    @Setter
    private AuthenticationApi authenticationApi;

    @Inject
    @Setter
    private Runtime runtime;

    /**
     * Testing basic injection of basic component for authentication entity.
     */
    @Test
    @Order(1)
    void componentsInsantiatedCorrectly() {
        this.authenticationApi = this.componentRegistry.findComponent(AuthenticationApi.class, null);
        Assertions.assertNotNull(this.authenticationApi);
        Assertions.assertNotNull(this.componentRegistry.findComponent(AuthenticationSystemApi.class, null));
    }

    @Test
    @Order(2)
    void testLogin() {
        Authenticable auth = authenticationApi.login("admin", "admin");
        Assertions.assertNotNull(auth);
        //testing login with default created user
        String token = authenticationApi.generateToken(auth);
        Assertions.assertNotNull(token);
    }
}
