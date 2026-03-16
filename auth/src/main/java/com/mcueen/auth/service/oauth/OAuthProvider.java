package com.mcueen.auth.service.oauth;

public interface OAuthProvider {
    OAuthUserInfo validateToken(String token);
    String getProviderName();
}
