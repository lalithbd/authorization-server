package com.mcueen.auth.util.auth;

public final class AuthErrorMessages {

    private AuthErrorMessages() {}

    public static final String INVALID_CLIENT = "Invalid client";
    public static final String INVALID_CLIENT_CREDENTIALS = "Invalid client credentials";
    public static final String INVALID_CREDENTIALS = "Invalid credentials";
    public static final String INVALID_AUTHORIZATION = "Invalid authorization";
    public static final String INVALID_REFRESH_TOKEN = "Invalid refresh token";
    public static final String REFRESH_TOKEN_REUSED = "Refresh token has already been used";
    public static final String REFRESH_TOKEN_LIFETIME_EXCEEDED = "Session has exceeded its maximum lifetime";
    public static final String EMAIL_NOT_VERIFIED = "Email not verified";
    public static final String INVALID_ID_TOKEN = "Invalid ID token";
    public static final String UNSUPPORTED_PROVIDER = "Unsupported provider: ";
    public static final String MISSING_PROVIDER_IDENTITY = "Provider did not supply a subject identifier";
    public static final String MISSING_PROVIDER_EMAIL = "Provider did not supply an email address";
    public static final String ACCOUNT_ALREADY_LINKED = "Account is linked to a different provider identity";
    public static final String NULL_AUTHENTICATION = "Null authentication object";

    public static final String MISSING_TOKEN_PARAMETER = "Missing required parameter: token";

    // RFC 6749 section 5.2 / RFC 7662 error codes
    public static final String ERROR_INVALID_CLIENT = "invalid_client";
    public static final String ERROR_INVALID_REQUEST = "invalid_request";
    public static final String ERROR_INVALID_GRANT = "invalid_grant";

    public static final String INVALID_CREDENTIALS_JSON = "{\"error\": \"Invalid username or password\"}";
    public static final String INVALID_CLIENT_CREDENTIALS_JSON = "{\"error\": \"Invalid Client credentials\"}";
}
