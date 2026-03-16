# Multi-Provider OAuth Integration Guide

## What is an ID Token / Access Token?

### ID Token (OpenID Connect)
- **Used by**: Google, Microsoft (Azure AD), Apple
- **Purpose**: Proves user identity
- **Format**: JWT containing user info (email, name, ID)
- **Validation**: Verify signature and claims
- **Example**: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...`

### Access Token (OAuth 2.0)
- **Used by**: Facebook, GitHub, Twitter
- **Purpose**: Access user data from provider's API
- **Format**: Opaque string or JWT
- **Validation**: Call provider's API to get user info
- **Example**: `EAABwzLixnjYBO...`

## Supported Providers

| Provider | Token Type | Field Name | Validation Method |
|----------|-----------|------------|-------------------|
| Email | Password | `password` | BCrypt comparison |
| Google | ID Token | `token` | Google tokeninfo API |
| Microsoft | Access Token | `token` | Microsoft Graph API |
| Facebook | Access Token | `token` | Facebook Graph API |
| GitHub | Access Token | `token` | GitHub User API |

## API Usage

### Single Unified Endpoint: `/auth/login`

All providers use the same endpoint with different `provider` values.

### 1. Email/Password Authentication

```http
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "provider": "email",
  "email": "user@example.com",
  "password": "password123"
}
```

### 2. Google Authentication

```http
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "provider": "google",
  "email": "user@gmail.com",
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
}
```

**How to get Google ID Token:**
```javascript
// Web - Google Sign-In
google.accounts.id.initialize({
  client_id: 'YOUR_GOOGLE_CLIENT_ID',
  callback: (response) => {
    const idToken = response.credential; // This is what you send
  }
});
```

### 3. Microsoft Authentication

```http
POST /auth/login
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{
  "provider": "microsoft",
  "email": "user@outlook.com",
  "token": "EwAoA8l6BAAURSN/FHlDW5xN..."
}
```

**How to get Microsoft Access Token:**
```javascript
// Web - MSAL.js
const msalInstance = new msal.PublicClientApplication(config);
const response = await msalInstance.loginPopup();
const accessToken = response.accessToken; // This is what you send
```

## Adding New Providers

To add a new OAuth provider (e.g., Facebook, GitHub):

### Step 1: Create Provider Implementation

```java
@Service
public class FacebookOAuthProvider implements OAuthProvider {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Override
    public OAuthUserInfo validateToken(String accessToken) {
        // Call Facebook Graph API
        String url = "https://graph.facebook.com/me?fields=id,email,first_name,last_name&access_token=" + accessToken;
        // Parse response and return OAuthUserInfo
    }
    
    @Override
    public String getProviderName() {
        return "facebook";
    }
}
```

### Step 2: That's It!

The factory automatically discovers and registers the new provider via Spring's dependency injection.

## Client Integration Examples

### Web Application (React)

```javascript
// Google Sign-In
const handleGoogleLogin = async (credentialResponse) => {
  await loginToBackend('google', credentialResponse.credential);
};

// Microsoft Sign-In
const handleMicrosoftLogin = async () => {
  const response = await msalInstance.loginPopup();
  await loginToBackend('microsoft', response.accessToken);
};

const loginToBackend = async (provider, token) => {
  const response = await fetch('/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Basic ' + btoa('clientId:clientSecret')
    },
    body: JSON.stringify({ provider, token })
  });
  
  const { access_token, refresh_token } = await response.json();
  // Store tokens
};
```

### Android Application

```kotlin
// Google Sign-In
val account = GoogleSignIn.getLastSignedInAccount(this)
val idToken = account?.idToken
authenticateWithBackend("google", idToken)

// Microsoft Sign-In
val result = msalClient.acquireToken(activity, scopes)
val accessToken = result.accessToken
authenticateWithBackend("microsoft", accessToken)

fun authenticateWithBackend(provider: String, token: String) {
    val request = LoginRequest(provider = provider, token = token)
    // Make API call
}
```

### iOS Application

```swift
// Google Sign-In
GIDSignIn.sharedInstance.signIn(withPresenting: self) { result, error in
    let idToken = result?.user.idToken?.tokenString
    authenticateWithBackend(provider: "google", token: idToken)
}

// Microsoft Sign-In
msalClient.acquireToken(with: parameters) { result, error in
    let accessToken = result?.accessToken
    authenticateWithBackend(provider: "microsoft", token: accessToken)
}
```

## Database Schema

```sql
ALTER TABLE userTable 
ADD COLUMN oauth_provider VARCHAR(50),
ADD COLUMN oauth_provider_id VARCHAR(255),
ADD COLUMN auth_method VARCHAR(50);

CREATE INDEX idx_oauth_provider ON userTable(oauth_provider, oauth_provider_id);
```

## Architecture Benefits

### No New Parameters Needed!

The `token` field is generic and works for:
- Google ID tokens
- Microsoft access tokens
- Facebook access tokens
- Any future OAuth provider

### Automatic Provider Discovery

New providers are automatically registered when you create a class implementing `OAuthProvider`.

### Single Request Format

```json
{
  "provider": "any_provider_name",
  "email": "optional",
  "token": "provider_token_here"
}
```

## Token Flow Comparison

### Google (ID Token)
1. User signs in with Google
2. Google returns ID token (JWT)
3. Send ID token to your backend
4. Backend validates with Google's tokeninfo endpoint
5. Extract user info from token response

### Microsoft (Access Token)
1. User signs in with Microsoft
2. Microsoft returns access token
3. Send access token to your backend
4. Backend calls Microsoft Graph API with token
5. Extract user info from API response

### Email (Password)
1. User enters email/password
2. Send credentials to your backend
3. Backend validates against database
4. No external API call needed

## Response (Same for All Providers)

```json
{
  "access_token": "your_jwt_token",
  "refresh_token": "your_refresh_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

## Security Notes

1. **Token Validation**: All OAuth tokens are validated with provider's API
2. **Email Verification**: Only verified emails are accepted
3. **Account Linking**: Users can link multiple providers to one account
4. **Client Credentials**: Required for all requests
5. **HTTPS Only**: Always use HTTPS in production

## Testing

```bash
# Email
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"provider":"email","email":"test@example.com","password":"pass123"}'

# Google
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"provider":"google","token":"GOOGLE_ID_TOKEN"}'

# Microsoft
curl -X POST http://localhost:8080/auth/login \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"provider":"microsoft","token":"MICROSOFT_ACCESS_TOKEN"}'
```
