package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.util.auth.AuthConstants;
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

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Component
public class AuthenticationProviderHelper {

    @Autowired
    @Lazy
    private OAuth2TokenGenerator<?> tokenGenerator;

    @Autowired
    @Lazy
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    public OAuth2Authorization getOAuth2Authorization(Authentication authentication, RegisteredClient client) {
        return getOAuth2Authorization(authentication, client, AuthorizationGrantType.PASSWORD);
    }

    public OAuth2Authorization getOAuth2Authorization(Authentication authentication, RegisteredClient client, AuthorizationGrantType grantType) {
        // A fresh login starts a new family, dated now.
        return getOAuth2Authorization(authentication, client, grantType, null, null);
    }

    /**
     * Issues a token pair, optionally continuing an existing rotation family.
     *
     * @param familyId      the family to continue, or null to start a new one
     * @param grantIssuedAt when the family's original login happened, or null for a new family
     */
    public OAuth2Authorization getOAuth2Authorization(Authentication authentication, RegisteredClient client,
                                                      AuthorizationGrantType grantType,
                                                      String familyId, Instant grantIssuedAt) {
        String resolvedFamilyId = (familyId != null) ? familyId : UUID.randomUUID().toString();
        Instant resolvedGrantIssuedAt = (grantIssuedAt != null) ? grantIssuedAt : Instant.now();

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
                .authorizationGrantType(grantType)
                // Carried as attributes so the persistence layer can stamp both tokens with the
                // family without every caller needing a rotation-aware signature.
                .attribute(AuthConstants.ATTR_FAMILY_ID, resolvedFamilyId)
                .attribute(AuthConstants.ATTR_GRANT_ISSUED_AT, resolvedGrantIssuedAt)
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
