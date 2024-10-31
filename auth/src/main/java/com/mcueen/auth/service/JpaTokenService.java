package com.mcueen.auth.service;

import com.mcueen.auth.model.user.OAuth2Token;
import com.mcueen.auth.repository.OAuth2TokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;


public interface JpaTokenService {
    void saveToken(OAuth2Token token);

    OAuth2Token findToken(Long tokenId);
}
