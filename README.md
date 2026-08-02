# OAuth2 Authorization Server

A production-ready OAuth2 Authorization Server built with Spring Boot 3 and Spring Security 6, featuring federated identity with multi-provider OAuth support (Google, Microsoft), custom authentication flows, refresh tokens, and token introspection.

## Features

- ✅ Username/Password Authentication
- ✅ Federated Identity (Google, Microsoft, extensible)
- ✅ Client Credentials Grant
- ✅ Refresh Token Flow
- ✅ Token Introspection
- ✅ Token Exchange Grant Type (RFC 8693)
- ✅ Client Credentials Validation
- ✅ Bearer Token Authentication
- ✅ Database-backed Token Storage
- ✅ Role-Based Access Control (RBAC)
- ✅ PostgreSQL Integration
- ✅ Auto User Registration via OAuth Providers
- ✅ Account Linking (Email ↔ OAuth)

## Tech Stack

- Java 21
- Spring Boot 3.3.1
- Spring Security OAuth2 Authorization Server
- Spring Data JPA
- PostgreSQL
- Gradle
- Lombok

## Prerequisites

- JDK 21+
- PostgreSQL 12+
- Gradle 8.8+

## Quick Start

### 1. Setup Database

```bash
docker run -d \
  --name auth-postgres \
  -p 5432:5432 \
  -e POSTGRES_DB=authServer \
  -e POSTGRES_USER=root \
  -e POSTGRES_PASSWORD=root \
  postgres:latest
```

### 2. Database Migration

Run the following SQL to support OAuth providers:

```sql
ALTER TABLE userTable
ADD COLUMN oauth_provider VARCHAR(50),
ADD COLUMN oauth_provider_id VARCHAR(255),
ADD COLUMN auth_method VARCHAR(50);

CREATE INDEX idx_oauth_provider ON userTable(oauth_provider, oauth_provider_id);
```

### 3. Configure Application

Edit `src/main/resources/application.yml`:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/authServer
    username: root
    password: root
```

### 4. Run Application

```bash
./gradlew bootRun
```

The server will start on `http://localhost:8080`

## API Documentation

### Authentication Endpoints

All authentication flows use a **single unified endpoint** (`/auth/login`) with a `provider` field to determine the authentication method.

#### 1. User Registration

```http
POST /users/signup
Content-Type: application/json

{
  "username": "john.doe",
  "email": "john@example.com",
  "password": "securePassword123"
}
```

**Response**: `201 Created`

#### 2. Login with Email/Password

```http
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "provider": "email",
  "email": "john@example.com",
  "password": "securePassword123"
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Grant Type stored**: `password`

#### 3. Login with Google

```http
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "provider": "google",
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2NTY..."
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Grant Type stored**: `urn:ietf:params:oauth:grant-type:token-exchange`

**Note**: The `token` field contains the Google ID Token obtained from Google Sign-In on the client side. The server validates this token with Google's API, creates/links the user account, and issues its own JWT tokens.

#### 4. Login with Microsoft

```http
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "provider": "microsoft",
  "token": "EwAoA8l6BAAURSN/FHlDW5xN..."
}
```

**Response**: Same format as above.

**Grant Type stored**: `urn:ietf:params:oauth:grant-type:token-exchange`

**Note**: The `token` field contains the Microsoft access token. The server validates it against Microsoft Graph API.

#### 5. Client Credentials Grant

```http
POST /auth/token
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read write
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Note**: This flow is for machine-to-machine authentication without user context.

#### 6. Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

#### 7. Token Introspection

```http
POST /auth/introspect
Content-Type: application/json

{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response**:
```json
{
  "active": true,
  "username": "john.doe",
  "exp": 1234567890,
  "client_id": "client-app"
}
```

### Protected Endpoints

#### Get All Users

```http
GET /users
Authorization: Bearer <access_token>
```

**Response**:
```json
[
  {
    "id": 1,
    "username": "john.doe",
    "email": "john@example.com"
  }
]
```

## Project Structure

```
auth/
├── src/main/java/com/mcueen/auth/
│   ├── config/
│   │   ├── security/
│   │   │   ├── filter/              # Custom authentication filters
│   │   │   ├── handler/             # Exception handlers
│   │   │   ├── model/               # Authentication models
│   │   │   ├── provider/            # Authentication providers
│   │   │   └── AuthorizationServerConfig.java
│   │   └── BeanConfig.java
│   ├── controller/                  # REST controllers
│   │   └── dto/                     # Data transfer objects
│   ├── model/                       # JPA entities
│   ├── repository/                  # Data repositories
│   ├── service/
│   │   ├── impl/                    # Service implementations
│   │   └── oauth/                   # OAuth provider integrations
│   │       ├── OAuthProvider.java           # Provider interface
│   │       ├── OAuthUserInfo.java           # Generic user info model
│   │       ├── OAuthProviderFactory.java    # Auto-discovery factory
│   │       ├── GoogleOAuthProvider.java     # Google implementation
│   │       └── MicrosoftOAuthProvider.java  # Microsoft implementation
│   ├── util/
│   │   ├── TokenType.java
│   │   └── auth/                    # Authentication constants
│   │       ├── AuthConstants.java           # Headers, providers, fields
│   │       ├── AuthEndpoints.java           # Endpoint paths
│   │       ├── AuthErrorMessages.java       # Error messages
│   │       └── AuthGrantTypes.java          # Grant types
│   └── Application.java
└── src/main/resources/
    └── application.yml
```

## Architecture

### Federated Identity Flow

The server acts as an **identity broker** supporting multiple authentication providers through a single unified endpoint.

```
┌─────────┐                    ┌──────────┐                    ┌─────────────┐
│ Client  │                    │   Your   │                    │   Google/   │
│   App   │                    │  Server  │                    │  Microsoft  │
└────┬────┘                    └────┬─────┘                    └──────┬──────┘
     │                              │                                  │
     │ 1. Sign in with Provider     │                                  │
     ├──────────────────────────────────────────────────────────────────>
     │                              │                                  │
     │ 2. Provider Token            │                                  │
     <───────────────────────────────────────────────────────────────────
     │                              │                                  │
     │ 3. POST /auth/login          │                                  │
     │    {provider, token}         │                                  │
     ├─────────────────────────────>│                                  │
     │                              │ 4. Validate Token                │
     │                              ├─────────────────────────────────>│
     │                              │ 5. User Info                     │
     │                              <──────────────────────────────────┤
     │                              │                                  │
     │                              │ 6. Create/Find/Link User         │
     │                              │ 7. Generate YOUR JWT tokens      │
     │                              │                                  │
     │ 8. YOUR access + refresh     │                                  │
     │    tokens                    │                                  │
     <──────────────────────────────┤                                  │
     │                              │                                  │
     │ 9. API calls with YOUR token │                                  │
     ├─────────────────────────────>│                                  │
     │                              │ 10. Validate YOUR token          │
     │                              │     (no provider call!)          │
     │ 11. Response                 │                                  │
     <──────────────────────────────┤                                  │
```

### Email/Password Authentication Flow

1. **Client** sends credentials to `/auth/login` with `provider: "email"` and Basic Auth (client credentials)
2. **UsernamePasswordAuthHandler** extracts provider and credentials
3. **FederatedAuthenticationProvider** routes to email authentication
4. **Client credentials** are validated against registered clients
5. **User credentials** are validated against the database
6. **OAuth2TokenGenerator** generates access and refresh tokens (grant type: `password`)
7. **OAuth2AuthorizationService** stores tokens in database
8. **Response** returns tokens to client

### OAuth Provider Authentication Flow

1. **Client** sends provider token to `/auth/login` with `provider: "google"` and Basic Auth
2. **UsernamePasswordAuthHandler** extracts provider and token
3. **FederatedAuthenticationProvider** routes to OAuth authentication
4. **Client credentials** are validated against registered clients
5. **OAuthProviderFactory** selects the correct provider implementation
6. **Provider token** is validated with the external provider's API
7. **User** is created, found, or linked in the database
8. **OAuth2TokenGenerator** generates access and refresh tokens (grant type: `token-exchange`)
9. **Response** returns YOUR tokens to client

### Token Validation Flow

1. **Client** sends request with `Authorization: Bearer <token>`
2. **CustomTokenHandler** extracts and validates token
3. **OAuth2AuthorizationService** checks token in database
4. **SecurityContext** is populated with authentication
5. **Request** proceeds to controller

### Grant Types

| Authentication Method | Grant Type | RFC |
|---|---|---|
| Email/Password | `password` | RFC 6749 |
| Google/Microsoft/OAuth | `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 |
| Client Credentials | `client_credentials` | RFC 6749 |
| Refresh Token | `refresh_token` | RFC 6749 |

### Account Linking

When a user authenticates with an OAuth provider:

1. **Existing OAuth user** → Authenticate directly
2. **Existing email user** → Link OAuth account, set auth method to `BOTH`
3. **New user** → Auto-create account with OAuth provider info

## Adding New OAuth Providers

To add a new provider (e.g., Facebook, GitHub), create a single class:

```java
@Service
public class FacebookOAuthProvider implements OAuthProvider {

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public OAuthUserInfo validateToken(String accessToken) {
        String url = "https://graph.facebook.com/me?fields=id,email,first_name,last_name&access_token=" + accessToken;
        // Parse response and return OAuthUserInfo
    }

    @Override
    public String getProviderName() {
        return "facebook";
    }
}
```

The `OAuthProviderFactory` automatically discovers and registers it via Spring's dependency injection. No other changes needed.

## Security Features

- **BCrypt Password Encoding**: Secure password hashing
- **Client Credentials**: Required for all token requests
- **Token Expiration**: Configurable token lifetimes
- **Database Token Storage**: Enables token revocation
- **RBAC**: Role and permission-based access control
- **Custom Error Handling**: Consistent JSON error responses
- **OAuth Token Validation**: External tokens validated with provider APIs
- **Email Verification**: Only verified OAuth emails are accepted
- **Independent Token Lifecycle**: Your tokens are independent of provider token expiry

## Configuration

### Database Configuration

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/authServer
    username: root
    password: root
    driver-class-name: org.postgresql.Driver
  jpa:
    hibernate:
      ddl-auto: update
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
```

### Server Configuration

```yaml
server:
  port: 8080
```

### Logging Configuration

```yaml
logging.level:
  org.springframework.security: DEBUG
  com.mcueen.auth: DEBUG
```

## Testing

### Using cURL

```bash
# Register user
curl -X POST http://localhost:8080/users/signup \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"password123"}'

# Login with Email/Password
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"provider":"email","email":"test@example.com","password":"password123"}'

# Login with Google
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","token":"GOOGLE_ID_TOKEN"}'

# Login with Microsoft
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"provider":"microsoft","token":"MICROSOFT_ACCESS_TOKEN"}'

# Client Credentials
curl -X POST http://localhost:8080/auth/token \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=client_credentials&scope=read write'

# Refresh Token
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"YOUR_REFRESH_TOKEN"}'

# Access protected endpoint
curl -X GET http://localhost:8080/users \
  -H "Authorization: Bearer <access_token>"
```

### Client Integration

#### Web (JavaScript)

```javascript
// Google Sign-In
google.accounts.id.initialize({
  client_id: 'YOUR_GOOGLE_CLIENT_ID',
  callback: async (response) => {
    const result = await fetch('/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + btoa('clientId:clientSecret')
      },
      body: JSON.stringify({
        provider: 'google',
        token: response.credential
      })
    });
    const { access_token, refresh_token } = await result.json();
  }
});
```

#### Android (Kotlin)

```kotlin
val account = GoogleSignIn.getLastSignedInAccount(this)
val idToken = account?.idToken

val request = LoginRequest(provider = "google", token = idToken)
// POST to /auth/login
```

#### iOS (Swift)

```swift
GIDSignIn.sharedInstance.signIn(withPresenting: self) { result, error in
    let idToken = result?.user.idToken?.tokenString
    let request = ["provider": "google", "token": idToken ?? ""]
    // POST to /auth/login
}
```

### Using Postman

1. Import the collection from `postman_collection.json`
2. Set environment variables for `baseUrl`, `clientId`, `clientSecret`
3. Run the requests in sequence

## Development

### Build Project

```bash
./gradlew build
```

### Run Tests

```bash
./gradlew test
```

### Generate JAR

```bash
./gradlew bootJar
```

The JAR will be in `build/libs/auth-0.0.1-SNAPSHOT.jar`

## Deployment

### Docker

```dockerfile
FROM eclipse-temurin:21-jre
COPY build/libs/auth-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

Build and run:
```bash
docker build -t auth-server .
docker run -p 8080:8080 \
  -e SPRING_DATASOURCE_URL=jdbc:postgresql://host.docker.internal:5432/authServer \
  auth-server
```

## Troubleshooting

### 404 Error on /auth/token

Ensure `AuthorizationServerSettings` matches security filter configuration:
```java
@Bean
public AuthorizationServerSettings providerSettings() {
    return AuthorizationServerSettings.builder()
            .tokenEndpoint(AuthEndpoints.TOKEN)
            .build();
}
```

### Database Connection Issues

Check PostgreSQL is running:
```bash
docker ps | grep postgres
```

### Token Not Valid

Check token expiration and ensure clock synchronization between services.

### Unsupported OAuth Provider

Ensure the provider name in the request matches the `getProviderName()` return value of your `OAuthProvider` implementation.

### Google Token Validation Fails

- Ensure the Google ID token is fresh (expires in 1 hour)
- Verify the token was issued for your Google Client ID
- Check network connectivity to `https://oauth2.googleapis.com/tokeninfo`

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

This project is licensed under the MIT License.

## Contact

For questions or support, please open an issue on GitHub.

## Acknowledgments

- Spring Security Team for the OAuth2 Authorization Server
- Spring Boot Team for the excellent framework
