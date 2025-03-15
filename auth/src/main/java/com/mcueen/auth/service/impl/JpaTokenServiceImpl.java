package com.mcueen.auth.service.impl;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.repository.OAuth2TokenRepository;
import com.mcueen.auth.service.JpaTokenService;
import com.mcueen.auth.util.TokenType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class JpaTokenServiceImpl implements JpaTokenService {

    @Autowired
    private OAuth2TokenRepository tokenRepository;

    @Override
    @Transactional
    public void saveToken(OAuth2TokenEntity token) {
        OAuth2TokenEntity tokenEntity = OAuth2TokenEntity.builder().build();
        tokenEntity.setIssuedAt(token.getIssuedAt());
        tokenEntity.setExpiresAt(token.getExpiresAt());
        tokenRepository.save(tokenEntity);
    }

    public OAuth2TokenEntity findByToken(String tokenValue) {
        return tokenRepository.findByTokenValue(tokenValue).orElse(null);
    }

    @Override
    @Transactional
    public void saveToken(OAuth2Token accessToken, OAuth2Token refreshToken, RegisteredClient registeredClient, String name) {
        OAuth2TokenEntity accessTokenEntity = OAuth2TokenEntity.builder()
                .tokenValue(accessToken.getTokenValue())
                .tokenType(TokenType.ACCESS.toString())
                .clientId(registeredClient.getClientId())
                .expiresAt(accessToken.getExpiresAt())
                .issuedAt(accessToken.getIssuedAt())
                .email(name).build();
        OAuth2TokenEntity refreshTokenEntity = OAuth2TokenEntity.builder()
                .tokenValue(refreshToken.getTokenValue())
                .tokenType(TokenType.REFRESH.toString())
                .clientId(registeredClient.getClientId())
                .expiresAt(refreshToken.getExpiresAt())
                .issuedAt(refreshToken.getIssuedAt())
                .email(name).build();
        tokenRepository.save(accessTokenEntity);
        tokenRepository.save(refreshTokenEntity);
    }
}
