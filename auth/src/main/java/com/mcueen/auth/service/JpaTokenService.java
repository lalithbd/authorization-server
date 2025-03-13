package com.mcueen.auth.service;

import com.mcueen.auth.model.user.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;


public interface JpaTokenService {

    void saveToken(OAuth2Token token);

    OAuth2Token findToken(Long tokenId);

    void saveToken(org.springframework.security.oauth2.core.OAuth2Token oAuth2Token, org.springframework.security.oauth2.core.OAuth2Token refreshToken, RegisteredClient registeredClient, String name);
}
