# OAuth2 Authorization Server

A production-ready OAuth2 Authorization Server built with Spring Boot 3 and Spring Security 6, featuring custom authentication flows, refresh tokens, and token introspection.

## Features

- ✅ Username/Password Authentication
- ✅ Client Credentials Grant
- ✅ Refresh Token Flow
- ✅ Token Introspection
- ✅ Client Credentials Validation
- ✅ Bearer Token Authentication
- ✅ Database-backed Token Storage
- ✅ Role-Based Access Control (RBAC)
- ✅ PostgreSQL Integration

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

### 2. Configure Application

Edit `src/main/resources/application.yml`:

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/authServer
    username: root
    password: root
```

### 3. Run Application

```bash
./gradlew bootRun
```

The server will start on `http://localhost:8080`

## API Documentation

### Authentication Endpoints

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

#### 2. Login (Get Access Token)

```http
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "username": "john.doe",
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

#### 3. Client Credentials Grant

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

#### 4. Refresh Token

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

#### 5. Token Introspection

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
│   │   └── security/
│   │       ├── filter/              # Custom authentication filters
│   │       ├── handler/             # Exception handlers
│   │       ├── model/               # Authentication models
│   │       ├── provider/            # Authentication providers
│   │       └── AuthorizationServerConfig.java
│   ├── controller/                  # REST controllers
│   ├── model/                       # JPA entities
│   ├── repository/                  # Data repositories
│   ├── service/                     # Business logic
│   └── Application.java
└── src/main/resources/
    └── application.yml
```

## Architecture

### Authentication Flow

1. **Client** sends credentials to `/auth/login` with Basic Auth (client credentials)
2. **UsernamePasswordAuthHandler** validates user and client credentials
3. **CustomPasswordAuthenticationProvider** authenticates the request
4. **OAuth2TokenGenerator** generates access and refresh tokens
5. **OAuth2AuthorizationService** stores tokens in database
6. **Response** returns tokens to client

### Token Validation Flow

1. **Client** sends request with `Authorization: Bearer <token>`
2. **CustomTokenHandler** extracts and validates token
3. **OAuth2AuthorizationService** checks token in database
4. **SecurityContext** is populated with authentication
5. **Request** proceeds to controller

## Security Features

- **BCrypt Password Encoding**: Secure password hashing
- **Client Credentials**: Required for all token requests
- **Token Expiration**: Configurable token lifetimes
- **Database Token Storage**: Enables token revocation
- **RBAC**: Role and permission-based access control
- **Custom Error Handling**: Consistent JSON error responses

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

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'

# Client Credentials
curl -X POST http://localhost:8080/auth/token \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'grant_type=client_credentials&scope=read write'

# Access protected endpoint
curl -X GET http://localhost:8080/users \
  -H "Authorization: Bearer <access_token>"
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
docker run -p 8080:8080 auth-server
```

## Troubleshooting

### 404 Error on /auth/token

Ensure `AuthorizationServerSettings` matches security filter configuration:
```java
@Bean
public AuthorizationServerSettings providerSettings() {
    return AuthorizationServerSettings.builder()
            .tokenEndpoint("/auth/token")
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
