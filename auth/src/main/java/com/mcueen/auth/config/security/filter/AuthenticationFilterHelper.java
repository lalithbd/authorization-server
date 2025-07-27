package com.mcueen.auth.config.security.filter;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
@Slf4j
public class AuthenticationFilterHelper {

    @Autowired
    @Lazy
    private AuthenticationManager authenticationManager;

    public OAuth2AccessTokenResponse buildOAuth2AccessTokenResponse(Authentication authentication) {
        ClientUserAuthenticationToken authenticated = (ClientUserAuthenticationToken) authenticationManager.authenticate(authentication);
        if (authentication == null) {
            log.error("NUll authentication object");
            throw new NullPointerException("NUll authentication object");
        }
        OAuth2AccessToken accessToken = authenticated.getAccessToken();
        OAuth2RefreshToken refreshToken = authenticated.getRefreshToken();
        if (accessToken == null || refreshToken == null) {
            log.error("NUll authentication object");
            throw new NullPointerException("NUll authentication object");
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(authenticated.getAccessToken().getTokenValue())
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .refreshToken(authenticated.getRefreshToken().getTokenValue())
                .scopes(authenticated.getAccessToken().getScopes());
        Instant issuedAt = accessToken.getIssuedAt();
        if (issuedAt != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(issuedAt, authenticated.getAccessToken().getExpiresAt()));
        }
        return builder.build();
    }
}
