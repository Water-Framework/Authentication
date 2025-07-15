# Authentication Module

## Module Goal

The Authentication module provides a comprehensive authentication system for the Water Framework. It handles user authentication through multiple providers, JWT token generation, and JAAS integration. The module supports both REST API and system-level authentication, allowing applications to authenticate users and generate secure tokens for subsequent API calls.

## Module Technical Characteristics

The Authentication module is built using the following technologies and patterns:

- **OSGi Framework**: Primary implementation using OSGi bundles for modular architecture
- **Spring Framework**: Alternative implementation for Spring-based applications
- **JWT (JSON Web Tokens)**: Secure token generation and validation using Nimbus JOSE JWT library
- **JAAS (Java Authentication and Authorization Service)**: Integration with Java's authentication framework
- **REST API**: JAX-RS based REST endpoints for authentication operations
- **Component Registry**: Dynamic discovery and registration of authentication providers
- **BouncyCastle**: Cryptographic operations for secure token handling

### Architecture Components

1. **AuthenticationApi**: Public API for authentication operations with permission checks
2. **AuthenticationSystemApi**: Internal API that bypasses permission system for system-level operations
3. **AuthenticationRestApi**: REST interface exposing authentication endpoints
4. **AuthenticationProvider**: Interface for implementing custom authentication providers
5. **JwtTokenService**: Service for JWT token generation and validation
6. **AuthenticationModule**: JAAS login module for integration with Java security

## Permission and Security

The Authentication module implements a multi-layered security approach:

- **Permission-based Access**: The `AuthenticationApi` enforces permission checks through the Water Framework's permission system
- **System-level Access**: The `AuthenticationSystemApi` bypasses permission checks for internal system operations
- **JWT Security**: Tokens are cryptographically signed and validated using keystore-based certificates
- **Provider-based Authentication**: Supports multiple authentication providers with issuer-based routing
- **JAAS Integration**: Provides JAAS login module for integration with Java security frameworks

### Security Features

- **Keystore-based JWT Signing**: Uses configured keystore for token signing
- **Issuer-based Provider Selection**: Routes authentication requests to appropriate providers
- **Token Expiration**: Configurable token lifetime with automatic expiration
- **Secure Password Handling**: Password validation through authentication providers
- **Principal Management**: JAAS principal creation for authenticated users

## How to Use It

### Importing the Module

#### For OSGi Applications:
```gradle
implementation group: 'it.water.authentication', name: 'Authentication-api', version: project.waterVersion
implementation group: 'it.water.authentication', name: 'Authentication-service', version: project.waterVersion
```

#### For Spring Applications:
```gradle
implementation group: 'it.water.authentication', name: 'Authentication-service-spring', version: project.waterVersion
```

### Basic Setup

1. **Configure Keystore Properties**:
```properties
water.keystore.password=your-keystore-password
water.keystore.alias=server-cert
water.keystore.file=path/to/your/keystore
water.private.key.password=your-private-key-password
```

2. **Configure Authentication Properties**:
```properties
water.authentication.service.issuer=it.water.core.api.model.User
water.rest.security.jwt.duration.millis=3600000
```

3. **Import Required Modules**:
   - For default User issuer: Import `it.water.user:User-service` (OSGi) or `it.water.user:User-service-spring` (Spring)

### Usage Examples

#### REST API Authentication
```bash
POST /water/authentication/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin
```

Response:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Programmatic Authentication
```java
@Inject
private AuthenticationApi authenticationApi;

// Login and get authenticable
Authenticable user = authenticationApi.login("username", "password");

// Generate JWT token
String token = authenticationApi.generateToken(user);
```

#### JAAS Integration
```java
// Configure JAAS to use the AuthenticationModule
LoginContext loginContext = new LoginContext("WaterAuth", callbackHandler);
loginContext.login();
```

## Properties and Configurations

### Required Properties

| Property | Description | Default | Required |
|----------|-------------|---------|----------|
| `water.keystore.password` | Keystore password for JWT signing | - | Yes |
| `water.keystore.alias` | Certificate alias in keystore | `server-cert` | Yes |
| `water.keystore.file` | Path to keystore file | - | Yes |
| `water.private.key.password` | Private key password | - | Yes |
| `water.authentication.service.issuer` | Issuer name for authentication provider selection | - | Yes |
| `water.rest.security.jwt.duration.millis` | JWT token expiration time in milliseconds | `3600000` (1 hour) | No |

### Optional Properties

| Property | Description | Default |
|----------|-------------|---------|
| `water.testMode` | Enable test mode for development | `false` |

### Keystore Configuration

The module requires a Java keystore (JKS) file with:
- A certificate with alias `server-cert` (or configured alias)
- Private key for JWT signing
- Proper password protection

Example keystore creation:
```bash
keytool -genkeypair -alias server-cert -keyalg RSA -keysize 2048 \
  -keystore server.keystore -storepass your-password \
  -keypass your-key-password -validity 365
```

## How to Customize Behaviours

### Custom Authentication Provider

Implement the `AuthenticationProvider` interface to create custom authentication logic:

```java
@FrameworkComponent
public class CustomAuthenticationProvider implements AuthenticationProvider {
    
    @Override
    public Collection<String> issuersNames() {
        return List.of("custom.issuer");
    }
    
    @Override
    public Authenticable login(String username, String password) {
        // Custom authentication logic
        return customAuthenticate(username, password);
    }
}
```

### Custom JAAS Module

Extend the `AuthenticationModule` class for custom JAAS integration:

```java
public class CustomAuthenticationModule extends AuthenticationModule {
    
    @Override
    protected void postAuthentication(Authenticable authenticated) {
        // Custom post-authentication logic
    }
    
    @Override
    protected void setAdditionalPrincipals(Set<Principal> principals) {
        // Add custom principals
    }
    
    @Override
    protected List<Role> getRoles(Authenticable authenticable) {
        // Custom role retrieval logic
        return customGetRoles(authenticable);
    }
    
    @Override
    protected AuthenticationApi getAuthenticationApi() {
        // Return your authentication API instance
        return customAuthenticationApi;
    }
}
```

### Custom Token Service

Override the JWT token service for custom token handling:

```java
@FrameworkComponent
public class CustomJwtTokenService implements JwtTokenService {
    
    @Override
    public String generateJwtToken(Authenticable authenticable) {
        // Custom token generation logic
        return customGenerateToken(authenticable);
    }
    
    @Override
    public Authenticable validateJwtToken(String token) {
        // Custom token validation logic
        return customValidateToken(token);
    }
}
```

### Custom Authentication Options

Implement custom authentication options for dynamic configuration:

```java
@FrameworkComponent
public class CustomAuthenticationOption implements AuthenticationOption {
    
    @Override
    public String getIssuerName() {
        // Dynamic issuer selection logic
        return determineIssuerName();
    }
}
```

### REST API Customization

Extend the REST API for additional endpoints:

```java
@Path("/authentication")
@FrameworkRestApi
public interface CustomAuthenticationRestApi extends AuthenticationRestApi {
    
    @POST
    @Path("/refresh")
    @Produces(MediaType.APPLICATION_JSON)
    Map<String, String> refreshToken(@HeaderParam("Authorization") String token);
}
```

### Integration with External Systems

The module supports integration with external authentication systems through:

1. **Custom Authentication Providers**: Implement `AuthenticationProvider` for external systems
2. **Custom JAAS Modules**: Extend `AuthenticationModule` for external JAAS integration
3. **Custom Token Services**: Override JWT handling for external token systems
4. **Multiple Issuers**: Support multiple authentication sources through issuer-based routing

### Testing Customizations

The module includes comprehensive test utilities:

```java
@ExtendWith(WaterTestExtension.class)
class CustomAuthenticationTest {
    
    @Inject
    private AuthenticationApi authenticationApi;
    
    @Test
    void testCustomAuthentication() {
        // Test custom authentication logic
        Authenticable user = authenticationApi.login("test", "password");
        assertNotNull(user);
        
        String token = authenticationApi.generateToken(user);
        assertNotNull(token);
    }
}
```

The Authentication module provides a robust, extensible authentication system that can be customized for various use cases while maintaining security and performance standards.