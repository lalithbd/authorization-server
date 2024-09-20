package com.mcueen.auth.config.security.model;

import com.mcueen.auth.model.user.OAuth2Token;
import com.mcueen.auth.repository.OAuth2TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class JpaTokenService {

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
}
