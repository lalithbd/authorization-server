package com.mcueen.auth.config.security.model;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.repository.OAuth2TokenRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Slf4j
@Transactional(readOnly = true)
public class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {

    @Autowired
    private OAuth2TokenRepository tokenRepository;

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        tokenRepository.deleteAllByClientIdAndEmailIsNull(authorization.getPrincipalName());
        OAuth2AccessToken accessTokenToken = authorization.getAccessToken().getToken();
        OAuth2TokenEntity accessTokenEntity = OAuth2TokenEntity.builder()
                .tokenValue(accessTokenToken.getTokenValue())
                .oAuth2TokenType(OAuth2TokenType.ACCESS_TOKEN.getValue())
                .clientId(authorization.getPrincipalName())
                .expiresAt(accessTokenToken.getExpiresAt())
                .authorizationId(authorization.getId())
                .issuedAt(accessTokenToken.getIssuedAt())
                .scopes(accessTokenToken.getScopes().stream().toList())
                .build();
        tokenRepository.save(accessTokenEntity);
    }

    @Transactional
    public void save(OAuth2Authorization authorization, String email) {
        tokenRepository.deleteAllByEmail(email);
        OAuth2AccessToken accessTokenToken = authorization.getAccessToken().getToken();
        OAuth2TokenEntity accessTokenEntity = OAuth2TokenEntity.builder()
                .tokenValue(accessTokenToken.getTokenValue())
                .oAuth2TokenType(OAuth2TokenType.ACCESS_TOKEN.getValue())
                .clientId(authorization.getPrincipalName())
                .expiresAt(accessTokenToken.getExpiresAt())
                .authorizationId(authorization.getId())
                .issuedAt(accessTokenToken.getIssuedAt())
                .scopes(accessTokenToken.getScopes().stream().toList())
                .email(email)
                .build();
        if (authorization.getRefreshToken() != null) {
            OAuth2RefreshToken refreshTokenToken = authorization.getRefreshToken().getToken();
            OAuth2TokenEntity refreshTokenEntity = OAuth2TokenEntity.builder()
                    .tokenValue(refreshTokenToken.getTokenValue())
                    .oAuth2TokenType(OAuth2TokenType.REFRESH_TOKEN.getValue())
                    .clientId(authorization.getPrincipalName())
                    .authorizationId(authorization.getId())
                    .expiresAt(refreshTokenToken.getExpiresAt())
                    .issuedAt(refreshTokenToken.getIssuedAt())
                    .email(email).build();
            tokenRepository.save(refreshTokenEntity);
        }
        tokenRepository.save(accessTokenEntity);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        log.info(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        List<OAuth2TokenEntity> auth2TokenEntities = tokenRepository.findAllByAuthorizationId(id);
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        OAuth2TokenEntity auth2TokenEntity = tokenRepository.findByTokenValueAndoAuth2TokenType(token, tokenType.getValue());

        return null;
    }

    public OAuth2TokenEntity findByTokenValueAndTokenType(String token, OAuth2TokenType tokenType) {
        return tokenRepository.findByTokenValueAndoAuth2TokenType(token, tokenType.getValue());
    }
}
