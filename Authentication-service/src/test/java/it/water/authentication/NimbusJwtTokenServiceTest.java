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

import it.water.authentication.api.AuthenticationApi;
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

/**
 * M13 unit tests for NimbusJwtTokenService.
 *
 * Verifies:
 *  - a generated token contains a jti (non-null, non-blank)
 *  - a generated token contains an iat (issued-at), implicitly verified through successful validation
 *  - after revokeToken(), validateToken() returns false for the revoked token
 *  - a non-revoked token still validates true
 *  - revokeToken(null) and revokeToken("") are no-ops (idempotent/safe)
 */
@ExtendWith(WaterTestExtension.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class NimbusJwtTokenServiceTest implements Service {

    @Inject
    @Setter
    private ComponentRegistry componentRegistry;

    @Inject
    @Setter
    private AuthenticationApi authenticationApi;

    @Inject
    @Setter
    private JwtTokenService jwtTokenService;

    private static final List<String> VALID_ISSUERS = List.of(User.class.getName());

    /**
     * Generates a valid token for the bootstrap admin (admin/admin in testMode).
     */
    private String generateAdminToken() {
        Authenticable admin = authenticationApi.login("admin", "admin");
        return authenticationApi.generateToken(admin);
    }

    @Test
    @Order(1)
    void componentsInstantiatedCorrectly() {
        this.jwtTokenService = componentRegistry.findComponent(JwtTokenService.class, null);
        Assertions.assertNotNull(jwtTokenService,
                "JwtTokenService must be registered in the component registry");
    }

    @Test
    @Order(2)
    void generateToken_tokenIsNotNullOrBlank() {
        String token = generateAdminToken();
        Assertions.assertNotNull(token, "Generated token must not be null");
        Assertions.assertFalse(token.isBlank(), "Generated token must not be blank");
    }

    @Test
    @Order(3)
    void generateToken_tokenValidatesTrue() {
        String token = generateAdminToken();
        Assertions.assertTrue(
                jwtTokenService.validateToken(VALID_ISSUERS, token),
                "A freshly generated token must validate as true");
    }

    @Test
    @Order(4)
    void generateToken_tokenContainsJti() throws Exception {
        // Parse the token to assert jti is present (M13: generateClaims adds jwtID)
        String token = generateAdminToken();
        com.nimbusds.jwt.SignedJWT signedJWT = com.nimbusds.jwt.SignedJWT.parse(token);
        String jti = signedJWT.getJWTClaimsSet().getJWTID();
        Assertions.assertNotNull(jti, "Generated token must carry a non-null jti claim");
        Assertions.assertFalse(jti.isBlank(), "jti in generated token must not be blank");
    }

    @Test
    @Order(5)
    void generateToken_tokenContainsIat() throws Exception {
        // M13: generateClaims adds issueTime (iat)
        String token = generateAdminToken();
        com.nimbusds.jwt.SignedJWT signedJWT = com.nimbusds.jwt.SignedJWT.parse(token);
        java.util.Date iat = signedJWT.getJWTClaimsSet().getIssueTime();
        Assertions.assertNotNull(iat, "Generated token must carry a non-null iat (issued-at) claim");
    }

    @Test
    @Order(6)
    void revokeToken_revokedTokenValidatesFalse() {
        // M13: after logout (revokeToken), the same token must no longer validate
        String token = generateAdminToken();
        Assertions.assertTrue(
                jwtTokenService.validateToken(VALID_ISSUERS, token),
                "Pre-condition: token must be valid before revocation");

        jwtTokenService.revokeToken(token);

        Assertions.assertFalse(
                jwtTokenService.validateToken(VALID_ISSUERS, token),
                "After revokeToken(), validateToken() must return false for the revoked token");
    }

    @Test
    @Order(7)
    void revokeToken_onlyAffectsRevokedToken_otherTokensStillValid() {
        // Revoking token A must not invalidate independently generated token B
        String tokenA = generateAdminToken();
        String tokenB = generateAdminToken();

        jwtTokenService.revokeToken(tokenA);

        Assertions.assertFalse(
                jwtTokenService.validateToken(VALID_ISSUERS, tokenA),
                "Revoked token A must be invalid");
        Assertions.assertTrue(
                jwtTokenService.validateToken(VALID_ISSUERS, tokenB),
                "Non-revoked token B must still be valid after revoking token A");
    }

    @Test
    @Order(8)
    void revokeToken_nullToken_doesNotThrow() {
        // M13: revokeToken is idempotent and safe; null must be silently ignored
        Assertions.assertDoesNotThrow(() -> jwtTokenService.revokeToken(null),
                "revokeToken(null) must not throw");
    }

    @Test
    @Order(9)
    void revokeToken_blankToken_doesNotThrow() {
        Assertions.assertDoesNotThrow(() -> jwtTokenService.revokeToken(""),
                "revokeToken('') must not throw");
        Assertions.assertDoesNotThrow(() -> jwtTokenService.revokeToken("   "),
                "revokeToken(blank) must not throw");
    }

    @Test
    @Order(10)
    void revokeToken_garbageToken_doesNotThrow() {
        // Unparseable tokens must be silently ignored
        Assertions.assertDoesNotThrow(() -> jwtTokenService.revokeToken("not.a.jwt"),
                "revokeToken with unparseable input must not throw");
    }

    @Test
    @Order(11)
    void validateToken_nullToken_returnsFalse() {
        Assertions.assertFalse(
                jwtTokenService.validateToken(VALID_ISSUERS, null),
                "validateToken(null) must return false without throwing");
    }

    @Test
    @Order(12)
    void validateToken_garbageToken_returnsFalse() {
        Assertions.assertFalse(
                jwtTokenService.validateToken(VALID_ISSUERS, "garbage.token.here"),
                "validateToken with unparseable input must return false");
    }

    @Test
    @Order(13)
    void revokeToken_idempotent_revokesSameTokenTwice() {
        String token = generateAdminToken();
        Assertions.assertDoesNotThrow(() -> jwtTokenService.revokeToken(token),
                "First revocation must not throw");
        Assertions.assertDoesNotThrow(() -> jwtTokenService.revokeToken(token),
                "Duplicate revocation must not throw (idempotent)");
        Assertions.assertFalse(
                jwtTokenService.validateToken(VALID_ISSUERS, token),
                "Token must still be revoked after duplicate revocation");
    }
}
