
## Authentication

### Overview

The Authentication project provides a comprehensive authentication solution designed to be integrated into the Water ecosystem. It offers functionalities for user login, JWT generation, and integration with JAAS, catering to both standard and customized authentication needs. This module aims to simplify the process of securing applications by providing reusable components for authentication and authorization. It offers REST APIs for authentication purposes, making it versatile for various deployment scenarios, including standard Java and Spring-based environments.

The primary goal of this repository is to encapsulate the authentication logic into a modular and reusable component. The `Authentication-api` module defines the contract for authentication services, while the `Authentication-service` module offers a core implementation. The `Authentication-service-spring` module adapts the authentication service for Spring-based applications, leveraging Spring's dependency injection and configuration capabilities. This separation of concerns allows developers to easily integrate authentication into different types of applications within the Water ecosystem.

### Technology Stack

*   **Language:** Java
*   **Build Tool:** Gradle
*   **Frameworks:**
    *   Spring Boot (for the `Authentication-service-spring` module)
    *   Apache CXF (for REST service testing)
    *   JUnit Jupiter (for unit testing)
*   **Libraries:**
    *   SLF4J (for logging)
    *   Jakarta Validation API (for bean validation)
    *   Lombok (for reducing boilerplate code)
    *   Hibernate Validator (implementation of Jakarta Bean Validation)
    *   Jackson (for JSON processing)
    *   Bouncy Castle (for cryptographic operations)
    *   Nimbus JOSE+JWT (for JWT token handling)
    *   Atteo Classindex (for fast annotation indexing)
    *   Mockito (for mocking in unit tests)
    *   Karate DSL (for API testing)
    *   Spring Data JPA (for simplified data access)
*   **Testing:**
    *   JUnit 5
    *   Mockito
    *   Karate

### Directory Structure

```
Authentication/
├── Authentication-api/                 # Defines the core interfaces for authentication
│   ├── src/main/java/it/water/authentication/api/
│   │   ├── AuthenticationApi.java       # Basic authentication operations
│   │   ├── AuthenticationSystemApi.java # System-level authentication operations
│   │   ├── options/                     # Package for authentication options
│   │   │   └── AuthenticationOption.java# Interface to retrieve Authentication options
│   │   └── rest/                        # Package for REST API definitions
│   │       └── AuthenticationRestApi.java# REST API for authentication
│   └── build.gradle                   # Gradle build file for the API module
├── Authentication-service/             # Implements the authentication logic
│   ├── src/main/java/it/water/authentication/service/
│   │   ├── AuthenticationServiceImpl.java   # Implementation of AuthenticationApi
│   │   ├── AuthenticationSystemServiceImpl.java# Implementation of AuthenticationSystemApi
│   │   ├── AuthenticationOptionImpl.java  # Implementation of AuthenticationOption
│   │   ├── AuthenticationConstants.java     # Defines constants used in the service
│   │   ├── jaas/                          # Package for JAAS authentication module
│   │   │   └── AuthenticationModule.java  # JAAS authentication module
│   │   ├── rest/                          # Package for REST controller implementation
│   │   │   └── AuthenticationRestControllerImpl.java# REST endpoint for login
│   │   └── execption/                     # Package for custom exceptions
│   │       └── NoIssuerNameDefinedException.java# Exception for missing issuer name
│   ├── src/main/resources/             # Application resources
│   │   └── it.water.application.properties# Configuration properties
│   ├── src/test/java/it/water/authentication/  # Test classes
│   │   ├── AuthenticationApiTest.java       # Tests for AuthenticationApi
│   │   ├── AuthenticationRestApiTest.java     # Tests for AuthenticationRestApi
│   │   ├── TestAuthenticationModule.java    # Test Authentication Module
│   │   └── TestCallbackHandler.java       # Test Callback Handler
│   ├── src/test/resources/            # Test resources
│   │   ├── it.water.application.properties# Test properties
│   │   ├── karate-config.js             # Karate configuration
│   │   └── certs/                         # Certificates for testing
│   │       └── server.keystore            # Keystore file
│   └── build.gradle                   # Gradle build file for the service module
├── Authentication-service-spring/      # Spring-based implementation of the authentication service
│   ├── src/main/java/it/water/authentication/service/
│   │   ├── AuthenticationApplication.java # Main class for Spring Boot application
│   │   └── rest/spring/                   # Package for Spring REST controller
│   │       ├── AuthenticationSpringRestApi.java# Spring REST API interface
│   │       └── AuthenticationSpringRestControllerImpl.java# Spring REST controller implementation
│   ├── src/main/resources/             # Spring application resources
│   │   └── application.properties       # Spring configuration properties
│   ├── src/test/java/it/water/authentication/service/ # Spring test classes
│   │   └── AuthenticationRestSpringApiTest.java# Tests for Spring REST API
│   ├── src/test/resources/            # Spring test resources
│   │   └── karate-config.js             # Karate configuration
│   └── build.gradle                   # Gradle build file for the Spring service module
├── build.gradle                       # Root build file
├── gradle.properties                  # Gradle properties
└── settings.gradle                    # Gradle settings file
```

### Getting Started

1.  **Prerequisites:**
    *   Java Development Kit (JDK) 8 or higher
    *   Gradle 6.0 or higher

2.  **Cloning the Repository:**
    *   Clone the repository using the following command:
        ```
        git clone https://github.com/Water-Framework/Authentication.git
        ```

3.  **Build Steps:**
    *   Navigate to the root directory of the project.
    *   Run the following command to build the project:
        ```
        gradle build
        ```
    *   To run the tests, use the following command:
        ```
        gradle test
        ```
    *   To generate JaCoCo coverage reports, use:
        ```
        gradle jacocoRootReport
        ```

4.  **Configuration:**
    *   The authentication service relies on properties defined in `it.water.application.properties` (for `Authentication-service`) and `application.properties` (for `Authentication-service-spring`). Key properties include:
        *   `water.authentication.service.issuer`: Specifies the issuer name for JWT tokens.
        *   `water.keystore.password`: Password for the keystore.
        *   `water.keystore.alias`: Alias for the server certificate in the keystore.
        *   `water.keystore.file`: Path to the keystore file.
        *   `water.private.key.password`: Password for the private key.
        *   `water.rest.security.jwt.duration.millis`: Duration of the JWT token in milliseconds.

5.  **Module Usage:**

    *   **Authentication-api:** This module defines the core interfaces for authentication. To use it in an external project, add it as a dependency in your `build.gradle` file:

        ```gradle
        dependencies {
            implementation group: 'it.water.authentication', name: 'Authentication-api', version: project.AuthenticationVersion
        }
        ```

        You can then implement the `AuthenticationApi` or `AuthenticationSystemApi` interfaces to provide your own authentication logic.

    *   **Authentication-service:** This module provides a default implementation of the authentication logic. To use it, add it as a dependency in your `build.gradle` file:

        ```gradle
        dependencies {
            implementation group: 'it.water.authentication', name: 'Authentication-service', version: project.AuthenticationVersion
        }
        ```

        This module requires configuration via `it.water.application.properties`. Ensure that the necessary properties (e.g., `water.authentication.service.issuer`) are set.  To integrate the JAAS module, configure your Java security policy to use `it.water.authentication.service.jaas.AuthenticationModule`.

    *   **Authentication-service-spring:** This module provides a Spring-based implementation of the authentication service. To use it, add it as a dependency in your `build.gradle` file:

        ```gradle
        dependencies {
            implementation group: 'it.water.authentication', name: 'Authentication-service-spring', version: project.AuthenticationVersion
        }
        ```

        This module is a Spring Boot application. Configure the necessary properties in `application.properties`. You can then run the application as a standard Spring Boot application. It exposes REST endpoints for authentication.

        **Example:** To integrate the `Authentication-service-spring` module in another Spring Boot application, you would add it as a dependency, configure the data source and JWT properties in your `application.properties` file, and then use the exposed REST endpoints for user authentication. For instance, to configure the data source:

        ```properties
        spring.datasource.driver-class-name=org.hsqldb.jdbcDriver
        spring.datasource.username=sa
        spring.datasource.password=
        spring.datasource.url=jdbc:hsqldb:mem:testdb
        spring.jpa.hibernate.ddl-auto=create-drop
        ```

        and the JWT properties:

        ```properties
        water.keystore.password=water.
        water.keystore.alias=server-cert
        water.keystore.file=src/test/resources/certs/server.keystore
        water.private.key.password=water.
        water.rest.security.jwt.duration.millis=3600000
        ```

        Then, you can send a POST request to `/water/login` (assuming `server.servlet.context-path=/water` is set) with the username and password in the request body to authenticate a user and receive a JWT token.

### Functional Analysis

#### 1. Main Responsibilities of the System

The primary responsibility of the system is to authenticate users and provide a secure way to manage user sessions using JWTs. It offers a set of APIs and implementations to:

*   Verify user credentials.
*   Generate JWTs upon successful authentication.
*   Provide REST endpoints for authentication.
*   Integrate with JAAS for pluggable authentication.
*   Manage authentication options and configurations.

The system provides foundational services for user authentication, abstracting away the complexities of JWT generation and management, and offering a consistent API for different authentication schemes.

#### 2. Problems the System Solves

The system addresses the following problems:

*   **Authentication Complexity:** Simplifies the process of implementing user authentication in Java and Spring applications.
*   **Security:** Provides a secure mechanism for managing user sessions using JWTs.
*   **Integration:** Offers a pluggable architecture that allows integration with different authentication providers and schemes.
*   **Standardization:** Provides a standardized API for authentication across different applications within the Water ecosystem.
*   **Flexibility:** Supports both standard Java environments and Spring-based environments.

The system meets the needs of developers who require a robust and reusable authentication solution, reducing the effort and complexity involved in implementing authentication from scratch.

#### 3. Interaction of Modules and Components

The modules and components interact as follows:

*   The `AuthenticationRestControllerImpl` (or `AuthenticationSpringRestControllerImpl`) receives authentication requests from clients.
*   The controller delegates the authentication logic to the `AuthenticationServiceImpl`.
*   The `AuthenticationServiceImpl` uses the `AuthenticationSystemServiceImpl` to perform the actual authentication.
*   The `AuthenticationSystemServiceImpl` interacts with the `jwtTokenService` to generate JWTs.
*   The `AuthenticationModule` (JAAS) uses the `AuthenticationApi` to authenticate users within a JAAS context.
*   Configuration properties are loaded via `AuthenticationOptionImpl` to customize authentication behavior.

Dependency Injection (Spring) is used to manage dependencies between components, promoting loose coupling and testability. Interfaces like `AuthenticationApi` define contracts that allow for different implementations to be plugged in.

#### 4. User-Facing vs. System-Facing Functionalities

*   **User-Facing Functionalities:**
    *   REST endpoints for login (`/login`) exposed by `AuthenticationRestControllerImpl` and `AuthenticationSpringRestControllerImpl`. These endpoints allow users to authenticate and obtain JWTs.
*   **System-Facing Functionalities:**
    *   `AuthenticationApi`, `AuthenticationSystemApi`: Interfaces defining the authentication contract for internal components.
    *   `AuthenticationServiceImpl`, `AuthenticationSystemServiceImpl`: Implementations of the authentication logic used by other system components.
    *   `AuthenticationModule`: JAAS module for integrating with Java security infrastructure.
    *   `jwtTokenService`: Service for generating and managing JWTs.

The user-facing functionalities provide the entry point for authentication, while the system-facing functionalities provide the underlying logic and services required for authentication.

### Architectural Patterns and Design Principles Applied

*   **Layered Architecture:** The project is structured into API, service, and data access layers, promoting separation of concerns.
*   **Dependency Injection:** Spring is used for dependency injection in the `Authentication-service-spring` module, enabling loose coupling and testability.
*   **Interface-Based Design:** The use of interfaces (e.g., `AuthenticationApi`, `AuthenticationSystemApi`, `AuthenticationRestApi`) promotes loose coupling and allows for different implementations to be plugged in.
*   **Pluggable Authentication:** The JAAS module allows for pluggable authentication mechanisms, enabling integration with different authentication providers.
*   **RESTful API:** The project exposes a RESTful API for authentication, making it accessible to different types of clients.
*   **JWT (JSON Web Token):** Uses JWT for secure token-based authentication, providing a stateless and scalable authentication mechanism.
*   **Configuration via Properties:** The issuer name and other parameters are configurable via application properties, allowing for easy customization.
*   **Separation of Concerns:** Different modules address different concerns (API definition, service implementation, Spring integration), promoting modularity and maintainability.
*   **Interceptor Pattern:** The `Core-interceptors` module is used, which suggests the potential use of interceptors for pre- or post-processing of authentication requests.

### Weaknesses and Areas for Improvement

*   [ ] **Centralized Exception Handling:** Implement a centralized exception handling mechanism to handle exceptions consistently across the application. This includes defining a standard exception format and using a global exception handler to process exceptions.
*   [ ] **More Robust Input Validation:** Implement more robust input validation to prevent injection attacks and other security vulnerabilities. This includes validating all input parameters and using parameterized queries to prevent SQL injection.  Document the validation rules applied.
*   [ ] **Standardized Configuration:** Use a standardized configuration management approach to manage application properties. Consider using a configuration server or a more structured configuration format (e.g., YAML).
*   [ ] **Comprehensive Documentation:** Provide comprehensive documentation for the API and the different modules. This includes documenting all classes, methods, and configuration properties. Add usage examples for each module.
*   [ ] **Monitoring and Logging:** Implement monitoring and logging to track the health and performance of the application. This includes logging all authentication requests and errors, and monitoring key metrics such as authentication success rate and response time.
*   [ ] **Consider using OAuth 2.0 or OpenID Connect:** Evaluate the possibility of migrating to a more standardized and secure authentication and authorization framework like OAuth 2.0 or OpenID Connect.  This would improve interoperability and security.
*   [ ] **Improve JAAS Integration Documentation:** Provide more detailed documentation on how to configure and use the JAAS module, including examples of different authentication providers and scenarios.
*   [ ] **Implement Role-Based Access Control (RBAC):** Add RBAC capabilities to the authentication service, allowing for fine-grained control over user permissions and access to resources.
*   [ ] **Enhance Test Coverage:** Increase the test coverage of the authentication service, particularly for edge cases and error scenarios.
*   [ ] **Address Potential Password Storage Weakness:** Explicitly document and enforce secure password storage practices, ensuring that passwords are never stored in plaintext and that strong hashing algorithms are used.
*   [ ] **Clarify the Role of `AuthenticationSystemApi`:** Provide clear documentation outlining the intended use cases and differences between `AuthenticationApi` and `AuthenticationSystemApi`.
*   [ ] **Provide Example for Custom Authentication:** Include an example demonstrating how to implement a custom authentication scheme using the JAAS module.

### Further Areas of Investigation

*   **Performance Bottlenecks:** Investigate potential performance bottlenecks in the authentication process, particularly in the JWT generation and validation.
*   **Scalability Considerations:** Evaluate the scalability of the authentication service, considering factors such as the number of concurrent users and the size of the user base.
*   **Integrations with External Systems:** Research potential integrations with external identity providers (e.g., LDAP, Active Directory).
*   **Advanced Features:** Explore advanced features such as multi-factor authentication (MFA) and adaptive authentication.
*   **Token Revocation:** Implement a mechanism for revoking JWT tokens, allowing for immediate invalidation of user sessions.
*   **JWT Key Rotation:** Implement a strategy for rotating the keys used to sign JWT tokens, improving security and reducing the risk of key compromise.
*   **Session Management:** Investigate different session management strategies, such as using refresh tokens to extend the lifetime of user sessions.

### Attribution

Generated with the support of ArchAI, an automated documentation system.