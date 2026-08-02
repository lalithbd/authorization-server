# Building a Custom OAuth2 Authorization Server with Spring Boot 3

## Introduction

In this article, we'll build a production-ready OAuth2 Authorization Server using Spring Boot 3 and Spring Security 6. Unlike typical OAuth2 implementations that rely on default configurations, we'll create a custom solution with username/password authentication, refresh tokens, and token introspection.

## The Challenge with Spring Security 6

Spring Security 6 has deprecated the Resource Owner Password Credentials (ROPC) grant type, discouraging direct username/password authentication in favor of more secure flows like Authorization Code with PKCE. While this is excellent for browser-based applications, many real-world scenarios still require password-based authentication:

- **Mobile applications** that need direct user authentication
- **Legacy systems** migrating to OAuth2
- **Internal enterprise applications** with trusted clients
- **First-party applications** where the client and authorization server are owned by the same organization

### Why Spring Security Deprecated Password Grant

The OAuth2 specification itself discourages the password grant because:
- It exposes user credentials to the client application
- It doesn't support multi-factor authentication easily
- It bypasses the authorization server's login page
- It's vulnerable to credential theft

### Our Solution

This implementation provides a **secure middle ground** by:
1. **Requiring client credentials** alongside user credentials (dual authentication)
2. **Using custom filters** to maintain full control over the authentication flow
3. **Storing tokens in a database** for revocation and auditing
4. **Supporting refresh tokens** to minimize password exposure
5. **Implementing proper error handling** and security best practices

This approach allows you to use password-based authentication in Spring Boot 3 while maintaining security and flexibility.

## Tech Stack

- **Java 21**
- **Spring Boot 3.3.1**
- **Spring Security OAuth2 Authorization Server**
- **PostgreSQL** (for token and user storage)
- **Gradle** (build tool)

## Project Architecture

Our authorization server implements four main authentication flows:

1. **Username/Password Authentication** (`/auth/login`) - User login with dual authentication
2. **Client Credentials Grant** (`/auth/token`) - Service-to-service authentication
3. **Refresh Token Flow** (`/auth/refresh`) - Token renewal
4. **Token Introspection** (`/auth/introspect`) - Token validation

### Understanding the Two Authentication Flows

#### Username/Password Authentication (User Login)

**Who**: End users (humans) logging into your application

**What's Required**: 
- User credentials (username + password) in request body
- Client credentials (clientId + clientSecret) in Authorization header

**Purpose**: Authenticate a specific user and issue tokens on their behalf

**Token Contains**: User identity, roles, and permissions

**Use Case**: Mobile app user logs in, web app user authentication

```bash
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>  # Identifies the app
Content-Type: application/json

{
  "username": "john.doe",      # Identifies the user
  "password": "password123"
}
```

#### Client Credentials Grant (Service Authentication)

**Who**: Applications/services (machines) without a user context

**What's Required**: 
- Only client credentials (clientId + clientSecret) in Authorization header
- No user credentials needed

**Purpose**: Authenticate the application itself for service-to-service communication

**Token Contains**: Only client identity and scopes (no user information)

**Use Case**: Backend service calling another service, scheduled jobs, system operations

```bash
POST /auth/token
Authorization: Basic <base64(clientId:clientSecret)>  # Identifies the service
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read write
```

### Key Differences

| Aspect | Username/Password | Client Credentials |
|--------|------------------|--------------------|
| **Who authenticates** | User (human) | Application (machine) |
| **Credentials needed** | User + Client | Client only |
| **Token represents** | Specific user | Application itself |
| **User context** | Yes (user ID, roles) | No user context |
| **Use case** | User login | Service-to-service |
| **Refresh token** | Yes | No (not needed) |

### Why Both Client Credentials?

You might wonder: "If client credentials look like username/password, why use both?"

**User credentials** (username/password):
- Belong to the **end user**
- Stored in the user database
- Change when user updates password
- Represent **who the user is**

**Client credentials** (clientId/clientSecret):
- Belong to the **application**
- Stored in the OAuth2 client database
- Hardcoded in the app configuration
- Represent **which app is making the request**

This dual authentication provides:
1. **App verification**: Ensures only authorized apps can request tokens
2. **User verification**: Ensures the user is who they claim to be
3. **Audit trail**: Know both who accessed and from which app
4. **Revocation control**: Can revoke app access without affecting user

### Key Components

#### 1. Custom Authentication Filters

We use custom filters instead of Spring's default OAuth2 endpoints to have full control over the authentication process:

- **UsernamePasswordAuthHandler**: Handles login with username/password + client credentials
- **RefreshTokenHandler**: Issues new access tokens using refresh tokens
- **CustomTokenHandler**: Validates Bearer tokens for protected endpoints
- **TokenIntrospectionHandler**: Validates and returns token metadata

#### 2. Authentication Providers

- **CustomPasswordAuthenticationProvider**: Validates user credentials and client credentials
- **RefreshTokenAuthenticationProvider**: Validates refresh tokens

#### 3. Security Configuration

```java
@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/auth/token", "/auth/introspect").permitAll()
                        .anyRequest().authenticated())
                .addFilterAfter(usernamePasswordAuthHandler, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(refreshTokenHandler, UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(customTokenHandler, UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .build();
    }
}
```

## Database Schema

The application uses JPA with PostgreSQL to store:

- **Users** (with roles and permissions)
- **OAuth2 Clients** (client credentials)
- **OAuth2 Tokens** (access and refresh tokens)

Key entities:
- `User`, `Role`, `Permission`
- `OAuth2Client`
- `OAuth2TokenEntity`

## API Endpoints

### 1. User Registration

```bash
POST /users/signup
Content-Type: application/json

{
  "username": "john.doe",
  "email": "john@example.com",
  "password": "securePassword123"
}
```

### 2. Login (Get Access Token)

```bash
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "username": "john.doe",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 3. Client Credentials Grant

```bash
POST /auth/token
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read write
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

This flow is used for machine-to-machine authentication where no user context is required.

### 4. Refresh Token

```bash
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGc..."
}
```

### 5. Token Introspection

```bash
POST /auth/introspect
Content-Type: application/json

{
  "token": "eyJhbGc..."
}
```

**Response:**
```json
{
  "active": true,
  "username": "john.doe",
  "exp": 1234567890,
  "client_id": "client-app"
}
```

### 6. Protected Endpoints

```bash
GET /users
Authorization: Bearer <access_token>
```

## Key Implementation Details

### Custom Authentication Token

We created `ClientUserAuthenticationToken` to handle both user and client authentication:

```java
public class ClientUserAuthenticationToken extends AbstractAuthenticationToken {
    private final String username;
    private final String password;
    private final String clientId;
    private final String clientSecret;
    // ... constructor and methods
}
```

### Token Generation

Tokens are generated using Spring's `OAuth2TokenGenerator`:

```java
@Bean
public OAuth2TokenGenerator<?> tokenGenerator() {
    return new DelegatingOAuth2TokenGenerator(
        new OAuth2RefreshTokenGenerator(), 
        new OAuth2AccessTokenGenerator()
    );
}
```

### Custom Error Handling

We implemented `CustomAuthenticationEntryPoint` to return JSON error responses:

```java
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, 
                        AuthenticationException authException) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().write("{\"error\": \"Invalid authorization\"}");
    }
}
```

## Configuration

### application.yml

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/authServer
    username: root
    password: root
  jpa:
    hibernate:
      ddl-auto: update
server:
  port: 8080
```

### build.gradle

```gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-security'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-authorization-server'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    runtimeOnly 'org.postgresql:postgresql'
}
```

## Security Considerations

1. **Client Credentials**: Always sent via Basic Authentication header
2. **Password Encoding**: Use BCrypt for password hashing
3. **Token Storage**: Tokens stored in database for revocation capability
4. **HTTPS**: Always use HTTPS in production
5. **Token Expiration**: Configure appropriate token lifetimes

## Testing the Server

1. **Start PostgreSQL**:
```bash
docker run -d -p 5432:5432 -e POSTGRES_DB=authServer -e POSTGRES_USER=root -e POSTGRES_PASSWORD=root postgres
```

2. **Run the application**:
```bash
./gradlew bootRun
```

3. **Register a user**:
```bash
curl -X POST http://localhost:8080/users/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'
```

4. **Login**:
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

## Advantages of This Approach

1. **Works with Spring Boot 3**: Implements password authentication despite Spring Security 6's deprecation of ROPC grant
2. **Full Control**: Complete control over authentication flow with custom filters and providers
3. **Enhanced Security**: Requires both user credentials AND client credentials for authentication
4. **Custom Endpoints**: RESTful API design that fits modern application architectures
5. **Flexible Authentication**: Easy to add additional authentication methods (OAuth2 social login, SAML, etc.)
6. **Database-Backed**: All tokens stored for auditing, revocation, and compliance
7. **Production-Ready**: Includes error handling, logging, and security best practices
8. **Refresh Token Support**: Minimizes password exposure by using long-lived refresh tokens

## Conclusion

This custom OAuth2 Authorization Server solves a critical challenge in Spring Boot 3: implementing password-based authentication after Spring Security 6 deprecated the Resource Owner Password Credentials grant.

By using custom filters and authentication providers, we've created a solution that:
- **Maintains compatibility** with Spring Boot 3 and Spring Security 6
- **Enhances security** by requiring dual authentication (user + client credentials)
- **Provides flexibility** for real-world use cases like mobile apps and internal systems
- **Follows best practices** with token storage, refresh tokens, and proper error handling

The implementation demonstrates that you can still use password authentication in modern Spring applications when business requirements demand it, without sacrificing security or maintainability.

The complete source code demonstrates how to:
- Implement custom authentication filters that work with Spring Security 6
- Bypass the deprecated password grant while maintaining similar functionality
- Integrate with Spring Security OAuth2 Authorization Server
- Store tokens in a database for revocation and auditing
- Handle multiple authentication flows (password, client credentials, refresh token)
- Secure REST APIs with Bearer tokens

This approach is ideal for:
- **Mobile applications** requiring direct user authentication
- **First-party applications** where you control both client and server
- **Legacy system migrations** to OAuth2
- **Internal enterprise applications** with trusted clients
- **Any scenario** where Authorization Code flow isn't practical

## Next Steps

- Add support for authorization code grant type
- Implement token revocation endpoint
- Add rate limiting for authentication endpoints
- Integrate with external identity providers (Google, GitHub)
- Add comprehensive unit and integration tests
- Implement PKCE for enhanced security

---

**GitHub Repository**: [Link to your repository]

**Questions or feedback?** Leave a comment below!
