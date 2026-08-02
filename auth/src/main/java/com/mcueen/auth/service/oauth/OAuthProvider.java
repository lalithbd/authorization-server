package com.mcueen.auth.service.oauth;

import com.mcueen.auth.model.user.AuthProvider;

public interface OAuthProvider {
    OAuthUserInfo validateToken(String token);

    OAuthUserInfo exchangeCodeAndGetUserInfo(String code, String redirectUri, AuthProvider authProvider);

    String getProviderName();
}
