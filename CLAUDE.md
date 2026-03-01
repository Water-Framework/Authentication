# Authentication Module — JWT & Login

## Purpose
Handles all authentication concerns: user login, JWT token generation and validation, multi-provider authentication routing, and JAAS integration. This module does NOT manage user lifecycle (registration, activation) — that belongs to the `User` module. Authentication is the entry point for obtaining a JWT that authorizes all subsequent API calls.

## Sub-modules

| Sub-module | Runtime | Key Classes |
|---|---|---|
| `Authentication-api` | All | `AuthenticationApi`, `AuthenticationSystemApi`, `AuthenticationRestApi`, `AuthenticationProvider`, `AuthenticationOption`, `TokenResponseDto` |
| `Authentication-service` | Water/OSGi | Service implementations, `JwtTokenService`, `AuthenticationModule` (JAAS), REST controller |
| `Authentication-service-spring` | Spring Boot | Spring MVC REST controller, Spring Security integration |

## Authentication Flow

```
Client POST /water/authentication/login
  ↓ (username + password + issuer)
AuthenticationRestController
  ↓
AuthenticationSystemApi.login()
  ↓ (no permission check — public endpoint)
AuthenticationProvider.authenticate()  ← resolved by issuer
  ↓ (validate credentials against data source)
JwtTokenService.generateToken()
  ↓ (signs JWT with keystore private key)
TokenResponseDto { token, refreshToken, expiresIn }
```

## Key Interfaces

### AuthenticationApi / AuthenticationSystemApi
```java
// Public login — no authentication required
TokenResponseDto login(String username, String password, String issuer);

// Token refresh
TokenResponseDto refreshToken(String refreshToken, String issuer);

// Token validation
boolean validateToken(String token);

// Logout (token invalidation)
void logout(String token);
```

### AuthenticationProvider
Pluggable strategy for credential validation — one provider per `issuer`:

```java
public interface AuthenticationProvider {
    String getIssuer();                          // e.g., "water", "ldap", "oauth2"
    boolean authenticate(String username, String password);
    Map<String, Object> getClaims(String username); // extra JWT claims
}
```

Water's built-in `UserAuthenticationProvider` (in `User` module) validates against the `WaterUser` table.

### AuthenticationOption
Enumeration of available issuers — used by clients to discover which login providers are active.

## JWT Token Structure

```json
{
  "sub": "username",
  "iss": "water",
  "iat": 1700000000,
  "exp": 1700086400,
  "roles": ["admin"],
  "userId": 42,
  "admin": true
}
```

Signed with RSA private key from keystore. Verified with corresponding public key.

## JAAS Integration

`AuthenticationModule` implements `javax.security.auth.spi.LoginModule` for environments using JAAS-based security (e.g., Apache Karaf). Uses the same `AuthenticationProvider` chain.

## Required Configuration

```properties
# Keystore for JWT signing
water.keystore.file=/path/to/keystore.jks
water.keystore.password=changeit
water.keystore.alias=water-jwt

# Private key password
water.private.key.password=changeit

# Default issuer
water.authentication.service.issuer=water

# Token expiry (seconds)
water.authentication.token.expire.millis=86400000

# Refresh token expiry
water.authentication.refresh.token.expire.millis=604800000
```

## REST Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/water/authentication/login` | Login, returns JWT |
| `POST` | `/water/authentication/refresh` | Refresh JWT |
| `GET` | `/water/authentication/options` | List available issuers |
| `POST` | `/water/authentication/logout` | Invalidate token |

**Security:** Login and options endpoints are public (no JWT required). Logout requires a valid JWT.

## Adding a Custom AuthenticationProvider

```java
@FrameworkComponent
public class MyLdapAuthenticationProvider implements AuthenticationProvider {

    @Override
    public String getIssuer() { return "ldap"; }

    @Override
    public boolean authenticate(String username, String password) {
        // Validate against LDAP directory
        return ldapClient.bind(username, password);
    }

    @Override
    public Map<String, Object> getClaims(String username) {
        return Map.of("department", ldapClient.getDepartment(username));
    }
}
```

Registration is automatic via `@FrameworkComponent`. The `AuthenticationSystemApi` routes login requests to the correct provider by matching the `issuer` parameter.

## Dependencies
- `it.water.core:Core-api` — `ComponentRegistry`, `Runtime`
- `it.water.core:Core-security` — `SecurityContext`, `EncryptionUtil`
- `it.water.rest:Rest-api` — `RestApi`, JWT filter integration
- `com.nimbusds:nimbus-jose-jwt` — JWT generation and validation
- `org.bouncycastle:bcmail-jdk15on` — cryptographic operations

## Testing
- Unit tests use `WaterTestExtension` with `water.testMode=true`
- REST tests use Karate — NEVER JUnit direct calls to the REST controller
- Test keystore provided in `src/test/resources/testKeystore.jks`
- Disable JWT validation in tests:
  ```properties
  water.rest.security.jwt.validate=false
  water.testMode=true
  ```

## Code Generation Rules
- Custom authentication providers implement `AuthenticationProvider` and annotate with `@FrameworkComponent`
- Never hardcode credentials or keystore passwords — always use `ApplicationProperties`
- Token generation logic lives in `JwtTokenService` — reuse it, never reimplement
- `AuthenticationRestController` is tested **exclusively via Karate**
- `AuthenticationSystemApi.login()` bypasses permission interceptors — intentional for public access
