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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

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

    // -----------------------------------------------------------------------
    // #15/#16 — aud + nbf emission, algorithm pinning, round-trip, nbf-future
    // -----------------------------------------------------------------------

    @Test
    @Order(14)
    void generateToken_tokenContainsNonEmptyAudClaim() throws Exception {
        // #15: generateClaims must emit an aud claim; it defaults to the issuer
        String token = generateAdminToken();
        SignedJWT signedJWT = SignedJWT.parse(token);
        java.util.List<String> audience = signedJWT.getJWTClaimsSet().getAudience();
        Assertions.assertNotNull(audience, "Generated token must carry a non-null aud claim");
        Assertions.assertFalse(audience.isEmpty(), "Generated token aud claim must not be empty");
        Assertions.assertFalse(audience.get(0).isBlank(),
                "First aud entry must not be blank");
    }

    @Test
    @Order(15)
    void generateToken_tokenContainsNbfClaim() throws Exception {
        // #15: generateClaims sets nbf = issueTime; assert it is present and <= now
        String token = generateAdminToken();
        SignedJWT signedJWT = SignedJWT.parse(token);
        Date nbf = signedJWT.getJWTClaimsSet().getNotBeforeTime();
        Assertions.assertNotNull(nbf, "Generated token must carry a non-null nbf claim");
        long nowPlusLeeway = Instant.now().toEpochMilli() + 2_000L; // 2s tolerance for slow CI
        Assertions.assertTrue(nbf.getTime() <= nowPlusLeeway,
                "nbf must not be more than 2 s in the future (it should equal issue time)");
    }

    @Test
    @Order(16)
    void generateToken_nbfClaimEqualsIssueTime() throws Exception {
        // #15: nbf is set to issueTime in generateClaims — verify they are equal
        String token = generateAdminToken();
        SignedJWT signedJWT = SignedJWT.parse(token);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
        Date nbf = claims.getNotBeforeTime();
        Date iat = claims.getIssueTime();
        Assertions.assertNotNull(nbf, "nbf must be present");
        Assertions.assertNotNull(iat, "iat must be present");
        // nbf is set to the same Date object as iat; allow 1 s tolerance for clock resolution
        long diffMillis = Math.abs(nbf.getTime() - iat.getTime());
        Assertions.assertTrue(diffMillis < 1_000L,
                "nbf must equal iat (within 1 s); actual diff=" + diffMillis + " ms");
    }

    @Test
    @Order(17)
    void generateToken_roundTripValidation_passesWithAudAndNbf() {
        // #15: a freshly generated token (which now carries aud + nbf) must still pass validateToken
        // This ensures aud/nbf validation logic in verifySignature does not regress
        String token = generateAdminToken();
        Assertions.assertTrue(
                jwtTokenService.validateToken(VALID_ISSUERS, token),
                "Round-trip: a self-issued token with aud + nbf must still validate successfully (no regression)");
    }

    @Test
    @Order(18)
    void validateToken_nonRs256AlgorithmToken_returnsFalse() throws Exception {
        // #15 algorithm pinning: a token signed with HS256 (or any non-RS256 alg) must be rejected
        // by validateToken before any cryptographic check. We build an HS256-signed JWT using a
        // 32-byte HMAC key and assert validateToken returns false.
        byte[] hmacSecret = new byte[32];
        new java.security.SecureRandom().nextBytes(hmacSecret);
        JWSHeader hs256Header = new JWSHeader(JWSAlgorithm.HS256);
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("admin")
                .issuer(User.class.getName())
                .audience(User.class.getName())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .jwtID(UUID.randomUUID().toString())
                .build();
        SignedJWT hs256Jwt = new SignedJWT(hs256Header, claims);
        JWSSigner signer = new MACSigner(hmacSecret);
        hs256Jwt.sign(signer);
        String hs256Token = hs256Jwt.serialize();

        Assertions.assertFalse(
                jwtTokenService.validateToken(VALID_ISSUERS, hs256Token),
                "A token signed with HS256 must be rejected by algorithm pinning (must not validate as RS256)");
    }

    @Test
    @Order(19)
    void validateToken_tokenWithNbfFarInFuture_returnsFalse() throws Exception {
        // #15 nbf validation: a token whose nbf is far beyond the clock-skew leeway must be rejected.
        // We generate a fresh valid token, parse it, re-sign a claims set with nbf = now + 1 hour
        // using the service's own signing key (we cannot call generateClaims directly, so we build
        // a fresh claims set with the same issuer/aud but an nbf 1 h in the future).
        // Note: this requires signing with the private key loaded through the WaterTestExtension
        // runtime. We obtain the key via EncryptionUtil which is injected by the framework.
        it.water.core.api.security.EncryptionUtil encryptionUtil =
                componentRegistry.findComponent(it.water.core.api.security.EncryptionUtil.class, null);
        Assumptions.assumeTrue(encryptionUtil != null,
                "EncryptionUtil must be available; skipping test if not registered");

        java.security.interfaces.RSAPrivateKey privateKey =
                (java.security.interfaces.RSAPrivateKey) encryptionUtil.getServerKeyPair().getPrivate();

        long nowMillis = Instant.now().toEpochMilli();
        // nbf is 1 hour in the future — well beyond the default 60 s clock skew
        Date farFutureNbf = Date.from(Instant.ofEpochMilli(nowMillis + 3_600_000L));
        JWTClaimsSet futureNbfClaims = new JWTClaimsSet.Builder()
                .subject("admin")
                .issuer(User.class.getName())
                .audience(User.class.getName())
                .expirationTime(Date.from(Instant.ofEpochMilli(nowMillis + 7_200_000L)))
                .notBeforeTime(farFutureNbf)
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader rs256Header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        SignedJWT futureNbfJwt = new SignedJWT(rs256Header, futureNbfClaims);
        com.nimbusds.jose.crypto.RSASSASigner rs256Signer =
                new com.nimbusds.jose.crypto.RSASSASigner(privateKey);
        futureNbfJwt.sign(rs256Signer);
        String futureNbfToken = futureNbfJwt.serialize();

        Assertions.assertFalse(
                jwtTokenService.validateToken(VALID_ISSUERS, futureNbfToken),
                "A token whose nbf is 1 hour in the future must be rejected (nbf exceeds clock-skew leeway)");
    }
}
