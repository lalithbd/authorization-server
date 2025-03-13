package com.mcueen.auth.service.impl;

import com.mcueen.auth.model.user.OAuth2Token;
import com.mcueen.auth.repository.OAuth2TokenRepository;
import com.mcueen.auth.service.JpaTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public class JpaTokenServiceImpl implements JpaTokenService {

    @Autowired
    private OAuth2TokenRepository tokenRepository;

    public void saveToken(OAuth2Token token) {
        OAuth2Token tokenEntity = new OAuth2Token();
        tokenEntity.setIssuedAt(token.getIssuedAt());
        tokenEntity.setExpiresAt(token.getExpiresAt());
        tokenRepository.save(tokenEntity);
    }

    public OAuth2Token findToken(Long tokenId) {
        return tokenRepository.findById(tokenId).orElse(null);
    }

    @Override
    public void saveToken(org.springframework.security.oauth2.core.OAuth2Token oAuth2Token, org.springframework.security.oauth2.core.OAuth2Token refreshToken, RegisteredClient registeredClient, String name) {

    }
}
