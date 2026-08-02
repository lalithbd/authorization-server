package com.mcueen.auth.util.auth;

public final class AuthEndpoints {

    private AuthEndpoints() {}

    public static final String LOGIN = "/auth/login";
    public static final String TOKEN = "/auth/token";
    public static final String REFRESH = "/auth/refresh";
    public static final String INTROSPECT = "/auth/introspect";
    public static final String OAUTH2_INTROSPECT = "/oauth2/introspect";
    public static final String PROVIDERS = "/auth/providers";
    public static final String OAUTH_CALLBACK = "/auth/oauth/callback";
    public static final String SIGNUP = "/users/sign-up";

    public static final String SWAGGER_UI = "/swagger-ui/**";
    public static final String SWAGGER_HTML = "/swagger-ui.html";
    public static final String API_DOCS = "/v3/api-docs/**";
}
