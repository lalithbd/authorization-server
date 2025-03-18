package com.mcueen.auth.service;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;


public interface JpaTokenService {

    void saveToken(OAuth2TokenEntity token);

    OAuth2TokenEntity findByToken(String tokenValue);

    void saveToken(OAuth2Token oAuth2Token, OAuth2Token refreshToken, RegisteredClient registeredClient, String name);

    List<GrantedAuthority> getAuthorities(OAuth2TokenEntity auth2TokenEntity);
}
