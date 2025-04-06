package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.CustomOAuth2AuthorizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class AuthenticationProviderHelper {

    @Autowired
    @Lazy
    private OAuth2TokenGenerator<?> tokenGenerator;

    @Autowired
    @Lazy
    private CustomOAuth2AuthorizationService JdbcOAuth2AuthorizationService;

    public OAuth2Authorization getOAuth2Authorization(Authentication authentication, RegisteredClient client) {
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .principal(authentication)
                .registeredClient(client)
                .authorizedScopes(Set.of("read", "write"))
                .build();
        OAuth2AccessToken accessToken = (OAuth2AccessToken) tokenGenerator.generate(tokenContext);
        if (accessToken != null) {
            accessToken = convertRefreshToken(accessToken);
        }
        tokenContext = DefaultOAuth2TokenContext.builder()
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .principal(authentication)
                .registeredClient(client)
                .build();

        OAuth2RefreshToken refreshToken = (OAuth2RefreshToken) tokenGenerator.generate(tokenContext);
        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(client)
                .token(accessToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, "access_token"))
                .token(refreshToken)
                .authorizedScopes(Set.of("read", "write"))
                .principalName(client.getClientId()).authorizationGrantType(AuthorizationGrantType.PASSWORD).build();
        JdbcOAuth2AuthorizationService.save(authorization, authentication.getPrincipal().toString());
        return authorization;
    }

    private OAuth2AccessToken convertRefreshToken(OAuth2AccessToken accessToken) {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                accessToken.getTokenValue(),
                accessToken.getIssuedAt(),
                accessToken.getExpiresAt(),
                accessToken.getScopes()
        );
    }
}
