package com.mcueen.auth.config.security.model;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

//@Component
@Slf4j
public class CustomOAuth2AuthorizationService implements OAuth2AuthorizationService {

    @Override
    public void save(OAuth2Authorization authorization) {
        log.info(authorization.getId());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        log.info(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return null;
    }
}
