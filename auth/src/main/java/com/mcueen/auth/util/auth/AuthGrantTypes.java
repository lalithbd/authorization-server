package com.mcueen.auth.util.auth;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public final class AuthGrantTypes {

    private AuthGrantTypes() {}

    public static final AuthorizationGrantType PASSWORD = AuthorizationGrantType.PASSWORD;
    public static final AuthorizationGrantType CLIENT_CREDENTIALS = AuthorizationGrantType.CLIENT_CREDENTIALS;
    public static final AuthorizationGrantType REFRESH_TOKEN = AuthorizationGrantType.REFRESH_TOKEN;
    public static final AuthorizationGrantType TOKEN_EXCHANGE = new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:token-exchange");
}
