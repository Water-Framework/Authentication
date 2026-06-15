package it.water.authentication;

import it.water.authentication.api.AuthenticationApi;
import it.water.authentication.api.AuthenticationSystemApi;
import it.water.authentication.service.AuthenticationConstants;
import it.water.authentication.service.execption.NoIssuerNameDefinedException;
import it.water.core.api.bundle.ApplicationProperties;
import it.water.core.api.bundle.Runtime;
import it.water.core.api.model.User;
import it.water.core.api.registry.ComponentRegistry;
import it.water.core.api.security.Authenticable;
import it.water.core.api.service.Service;
import it.water.core.interceptors.annotations.Inject;
import it.water.core.testing.utils.junit.WaterTestExtension;
import it.water.service.rest.api.security.jwt.JwtTokenService;
import lombok.Setter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import java.security.Principal;
import java.util.HashMap;

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
    private ApplicationProperties applicationProperties;

    @Inject
    @Setter
    private Runtime runtime;

    @Inject
    @Setter
    private JwtTokenService jwtTokenService;

    /**
     * Testing basic injection of basic component for authentication entity.
     */
    @Test
    @Order(1)
    void componentsInsantiatedCorrectly() {
        //for coverage
        NoIssuerNameDefinedException ex = new NoIssuerNameDefinedException();
        Assertions.assertNotNull(ex);
        Assertions.assertNotNull(AuthenticationConstants.AUTHENTICATION_ISSUER_NAME);
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

    @Test
    @Order(3)
    void testJaasModule() {
        TestAuthenticationModule testAuthenticationModule = new TestAuthenticationModule(authenticationApi);

        Subject subjectOk = createSubject("admin", "admin");
        CallbackHandler testCallbackHandler = new TestCallbackHandler(subjectOk);
        testAuthenticationModule.initialize(subjectOk, testCallbackHandler, new HashMap<>(), new HashMap<>());
        Assertions.assertDoesNotThrow(testAuthenticationModule::abort);
        Assertions.assertDoesNotThrow(testAuthenticationModule::login);
        Assertions.assertDoesNotThrow(testAuthenticationModule::commit);
        Assertions.assertDoesNotThrow(testAuthenticationModule::logout);

        Subject subjectKo = createSubject("admin", "WrongPwd");
        testCallbackHandler = new TestCallbackHandler(subjectKo);
        testAuthenticationModule.initialize(subjectKo, testCallbackHandler, new HashMap<>(), new HashMap<>());
        Assertions.assertThrows(FailedLoginException.class, testAuthenticationModule::login);

        subjectKo = createSubject(null, "WrongPwd");
        testCallbackHandler = new TestCallbackHandler(subjectKo);
        testAuthenticationModule.initialize(subjectKo, testCallbackHandler, new HashMap<>(), new HashMap<>());
        Assertions.assertThrows(FailedLoginException.class, testAuthenticationModule::login);

        subjectKo = createSubject("admin", "");
        testCallbackHandler = new TestCallbackHandler(subjectKo);
        testAuthenticationModule.initialize(subjectKo, testCallbackHandler, new HashMap<>(), new HashMap<>());
        Assertions.assertThrows(FailedLoginException.class, testAuthenticationModule::login);
    }

    // -----------------------------------------------------------------------
    // M13 — Logout / token revocation via AuthenticationApi
    // -----------------------------------------------------------------------

    @Test
    @Order(4)
    void logout_revokedTokenValidatesFalse() {
        // M13: login → generateToken → logout → validateToken must return false
        Authenticable auth = authenticationApi.login("admin", "admin");
        String token = authenticationApi.generateToken(auth);
        List<String> validIssuers = List.of(User.class.getName());
        Assertions.assertTrue(
                jwtTokenService.validateToken(validIssuers, token),
                "Pre-condition: freshly generated token must be valid");

        authenticationApi.logout(token);

        Assertions.assertFalse(
                jwtTokenService.validateToken(validIssuers, token),
                "After logout, the token must no longer validate (M13)");
    }

    @Test
    @Order(5)
    void logout_nullToken_doesNotThrow() {
        // M13: logout is idempotent/safe — null must not surface an exception
        Assertions.assertDoesNotThrow(() -> authenticationApi.logout(null),
                "logout(null) must not throw");
    }

    @Test
    @Order(6)
    void logout_blankToken_doesNotThrow() {
        Assertions.assertDoesNotThrow(() -> authenticationApi.logout(""),
                "logout('') must not throw");
    }

    @Test
    @Order(7)
    void logout_garbageToken_doesNotThrow() {
        Assertions.assertDoesNotThrow(() -> authenticationApi.logout("not.a.jwt.token"),
                "logout with garbage input must not throw");
    }

    @Test
    @Order(8)
    void logout_idempotent_logoutSameTokenTwice() {
        // Calling logout twice on the same token must not throw and the token must stay invalid
        Authenticable auth = authenticationApi.login("admin", "admin");
        String token = authenticationApi.generateToken(auth);
        List<String> validIssuers = List.of(User.class.getName());

        Assertions.assertDoesNotThrow(() -> authenticationApi.logout(token),
                "First logout must not throw");
        Assertions.assertDoesNotThrow(() -> authenticationApi.logout(token),
                "Duplicate logout must not throw (idempotent)");
        Assertions.assertFalse(
                jwtTokenService.validateToken(validIssuers, token),
                "Token must remain invalid after duplicate logout");
    }

    private Subject createSubject(String username, String password) {
        Subject subject = new Subject();
        subject.getPrincipals().add(new Principal() {
            @Override
            public String getName() {
                return username;
            }
        });
        subject.getPrivateCredentials().add(password);
        return subject;
    }
}
