package com.mcueen.auth.util.auth;

public final class AuthConstants {

    private AuthConstants() {}

    // Headers
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final int BEARER_PREFIX_LENGTH = 7;
    public static final int BASIC_PREFIX_LENGTH = 6;

    // Providers
    public static final String PROVIDER_EMAIL = "email";
    public static final String PROVIDER_GOOGLE = "google";
    public static final String PROVIDER_MICROSOFT = "microsoft";

    // Auth Methods (stored in DB)
    public static final String AUTH_METHOD_EMAIL = "EMAIL";
    public static final String AUTH_METHOD_OAUTH = "OAUTH";
    public static final String AUTH_METHOD_BOTH = "BOTH";

    // Request Fields
    public static final String FIELD_PROVIDER = "provider";
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_PASSWORD = "password";
    public static final String FIELD_TOKEN = "token";
    public static final String FIELD_REFRESH_TOKEN = "refreshToken";
}
