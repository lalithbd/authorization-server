package com.mcueen.auth.config.security.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
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
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    public OAuth2Authorization getOAuth2Authorization(Authentication authentication, RegisteredClient client) {
        OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .principal(authentication)
                .registeredClient(client)
                .authorizedScopes(client.getScopes())
                .build();
        OAuth2AccessToken accessToken = (OAuth2AccessToken) tokenGenerator.generate(tokenContext);
        if (accessToken != null) {
            accessToken = convertRefreshToken(accessToken, client.getScopes());
        }
        tokenContext = DefaultOAuth2TokenContext.builder()
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .principal(authentication)
                .registeredClient(client)
                .authorizedScopes(client.getScopes())
                .build();

        OAuth2RefreshToken refreshToken = (OAuth2RefreshToken) tokenGenerator.generate(tokenContext);
        OAuth2Authorization auth2Authorization = OAuth2Authorization
                .withRegisteredClient(client)
                .token(accessToken, metadata -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, "access_token"))
                .token(refreshToken)
                .principalName(authentication.getName())
                .authorizedScopes(client.getScopes())
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .build();
        oAuth2AuthorizationService.save(auth2Authorization);
        return auth2Authorization;
    }

    private OAuth2AccessToken convertRefreshToken(OAuth2AccessToken accessToken, Set<String> scopes) {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                accessToken.getTokenValue(),
                accessToken.getIssuedAt(),
                accessToken.getExpiresAt(),
                scopes
        );
    }
}
