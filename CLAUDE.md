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

## Login Lockout & Brute-Force Protection (#34)

Failed logins are throttled by a `LoginAttemptStore` consulted inside `AuthenticationSystemServiceImpl.login(...)`. The protection has three dimensions:

### Per-IP lockout key
The counter key is **`issuer:ip:username`** (not `issuer:username`). Adding the source-IP dimension prevents a targeted account-lock DoS: an attacker who only knows a victim's username can no longer lock that account from anywhere, because each `(ip, username)` pair is throttled independently. When the IP cannot be resolved the key degrades to `issuer:unknown:username` (no regression vs. the old per-identity lock).

### Client-IP resolution (per-runtime, trusted-proxy aware)
The IP is a transport detail, so it is extracted **at the REST boundary** and passed explicitly to the system layer — it is **never** stuffed into the `SecurityContext` (which is transport-agnostic and also populated by JAAS / internal calls). Because the two runtimes use different servlet namespaces, extraction is per-runtime:

| Runtime | How the request is read | Class |
|---|---|---|
| JAX-RS / CXF | `@Context javax.servlet.http.HttpServletRequest` (field) | `AuthenticationRestControllerImpl.resolveClientIp()` |
| Spring MVC | `RequestContextHolder` → `jakarta.servlet.http.HttpServletRequest` | `AuthenticationSpringRestControllerImpl.resolveClientIp()` (override) |

The trust decision is centralized in the pure helper `ClientIpResolver`: `X-Forwarded-For` / `X-Real-IP` are honored **only** when the immediate TCP peer (`getRemoteAddr()`) is a configured trusted proxy (`water.authentication.trusted.proxies`, default empty → only the direct TCP source is used). Coordinated with the gateway's #37 trusted-proxy handling.

The IP is threaded through new, additive overloads (public contract unchanged):
`AuthenticationApi.login(u, p, clientIp)` → `AuthenticationSystemApi.login(u, p, issuer, clientIp)`.

### Progressive backoff
On reaching the failure threshold the key is locked; with backoff enabled the lock duration grows **exponentially with a cap** across repeated lockouts of the same key (`base × multiplier^n`, capped). A successful login (`recordSuccess`) clears the counter and resets the escalation. The default `InMemoryLoginAttemptStore` is per-JVM (multi-node → plug a shared store, e.g. Redis); it is bounded (stale-eviction + hard key cap) against credential-stuffing memory growth.

**testMode:** when `water.testMode=true` lockout enforcement is fully bypassed (the store is never consulted), so repeated wrong logins in tests don't trip it.

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

# Multitenancy enablement (issuer-side). true => login embeds the active company as the
# `companyId` JWT claim + downstream tenant enforcement applies. Default false = single-tenant.
water.authentication.multitenant.enabled=false

# Token expiry (seconds)
water.authentication.token.expire.millis=86400000

# Refresh token expiry
water.authentication.refresh.token.expire.millis=604800000

# --- Login lockout / brute-force protection (#34) ---
# Failed attempts within the window before the (issuer:ip:username) key is locked
water.authentication.login.lockout.threshold=5
water.authentication.login.lockout.window.millis=900000      # 15 min sliding window
water.authentication.login.lockout.duration.millis=900000    # base lock = 15 min
water.authentication.login.lockout.max.keys=100000           # hard cap on tracked keys (memory bound)
# Progressive backoff: lock = base * multiplier^(previous lockouts), capped
water.authentication.login.lockout.backoff.enabled=true
water.authentication.login.lockout.backoff.multiplier=2
water.authentication.login.lockout.max.duration.millis=3600000  # cap = 1 h
# Trusted reverse proxies (CSV); X-Forwarded-For/X-Real-IP honored only from these peers (default empty)
water.authentication.trusted.proxies=
```

## Multitenancy — Company-based (see the `multitenancy-knowledge` skill)

Enabled issuer-side via `water.authentication.multitenant.enabled` (default false → single-tenant, fully backward compatible: no `companyId` claim, no tenant filtering).

- **Login gate (in the provider, NOT here)**: additive overload `AuthenticationProvider.login(username, password, Long companyId)` (default delegates to the 2-arg). `AuthenticationSystemServiceImpl.login` calls the 3-arg only when MT is enabled; the membership validation lives in `UserAuthenticationProvider` (User domain): a normal user's requested `companyId` must be in its `UserCompany` membership (else `UnauthorizedException`), else the primary; an **admin is non-scoped** (returns `null` → cross-tenant, for provisioning). The resolved company is set on the returned `Authenticable` and emitted as the encrypted JWT claim `companyId` (`NimbusJwtTokenService.generateClaims`, only when non-null).
- **Impersonation (user-level)**: `AuthenticationApi.impersonate(targetUsername, companyId)` + endpoint `POST /water/authentication/impersonate` (authenticated). Permission-gated via `UserActions.IMPERSONATE` on `WaterUser` (admin by construction; a normal user only if granted). Mints a token with the TARGET's identity/company/roles + claim `impersonatedBy=<caller>` marking it non-genuine (audit). Not MT-flag-gated; same TTL.
- REST login accepts an optional `@FormParam companyId` (JAX-RS) / `@RequestParam companyId` (Spring); absent → null.

## REST Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/water/authentication/login` | Login, returns JWT (optional `companyId` for MT) |
| `POST` | `/water/authentication/refresh` | Refresh JWT |
| `GET` | `/water/authentication/options` | List available issuers |
| `POST` | `/water/authentication/logout` | Invalidate token |
| `POST` | `/water/authentication/impersonate` | (MT) Mint a token impersonating a target user; requires `IMPERSONATE` permission |

**Security:** Login and options endpoints are public (no JWT required). Logout and impersonate require a valid JWT.

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
