package com.mcueen.auth.util.auth;

public final class AuthEndpoints {

    private AuthEndpoints() {}

    public static final String LOGIN = "/auth/login";
    public static final String TOKEN = "/auth/token";
    public static final String REFRESH = "/auth/refresh";
    public static final String INTROSPECT = "/auth/introspect";
    public static final String OAUTH2_INTROSPECT = "/oauth2/introspect";
}
