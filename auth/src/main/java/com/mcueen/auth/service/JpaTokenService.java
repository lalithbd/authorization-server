package com.mcueen.auth.service;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;


public interface JpaTokenService {

    void saveToken(OAuth2TokenEntity token);

    OAuth2TokenEntity findByToken(String tokenValue);

    void saveToken(org.springframework.security.oauth2.core.OAuth2Token oAuth2Token, org.springframework.security.oauth2.core.OAuth2Token refreshToken, RegisteredClient registeredClient, String name);
}
