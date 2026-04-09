package com.mcueen.auth.util.auth;

public final class AuthErrorMessages {

    private AuthErrorMessages() {}

    public static final String INVALID_CLIENT = "Invalid client";
    public static final String INVALID_CLIENT_CREDENTIALS = "Invalid client credentials";
    public static final String INVALID_CREDENTIALS = "Invalid credentials";
    public static final String INVALID_AUTHORIZATION = "Invalid authorization";
    public static final String INVALID_REFRESH_TOKEN = "Invalid refresh token";
    public static final String EMAIL_NOT_VERIFIED = "Email not verified";
    public static final String NULL_AUTHENTICATION = "Null authentication object";

    public static final String INVALID_CREDENTIALS_JSON = "{\"error\": \"Invalid username or password\"}";
    public static final String INVALID_CLIENT_CREDENTIALS_JSON = "{\"error\": \"Invalid Client credentials\"}";
}
