package com.mcueen.auth.service.impl;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.provider.AuthenticationProviderHelper;
import com.mcueen.auth.controller.dto.AuthProviderDto;
import com.mcueen.auth.controller.dto.OAuthCallbackDto;
import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.AuthProviderRepository;
import com.mcueen.auth.service.AuthProviderService;
import com.mcueen.auth.service.FederatedIdentityService;
import com.mcueen.auth.service.oauth.OAuthProviderFactory;
import com.mcueen.auth.service.oauth.OAuthUserInfo;
import com.mcueen.auth.util.auth.AuthGrantTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
public class AuthProviderServiceImpl implements AuthProviderService {

    @Autowired
    private AuthProviderRepository authProviderRepository;

    @Autowired
    private OAuthProviderFactory oAuthProviderFactory;

    @Autowired
    private FederatedIdentityService federatedIdentityService;

    @Autowired
    private AuthenticationProviderHelper authenticationProviderHelper;

    @Override
    public List<AuthProviderDto> getEnabledProviders() {
        return authProviderRepository.findByEnabledTrue()
                .stream()
                .map(p -> new AuthProviderDto(p.getId(), p.getName(), p.getAuthorizationUrl(), p.getClientId(), p.getScope()))
                .toList();
    }

    @Override
    public OAuth2AccessTokenResponse handleOAuthCallback(OAuthCallbackDto callbackDto, RegisteredClient client) {
        // Get provider config from DB
        String provider = callbackDto.getProvider();
        AuthProvider authProvider = federatedIdentityService.requireEnabledProvider(provider);

        // Exchange code for user info
        OAuthUserInfo oauthUser = oAuthProviderFactory.getProvider(provider)
                .exchangeCodeAndGetUserInfo(callbackDto.getCode(), callbackDto.getRedirectUri(), authProvider);

        // Find, link, or create the account
        User user = federatedIdentityService.resolveUser(oauthUser, provider);

        // Generate tokens
        ClientUserAuthenticationToken authToken = new ClientUserAuthenticationToken(
                user.getEmail(), null, client.getClientId(), null);

        OAuth2Authorization auth2Authorization = authenticationProviderHelper
                .getOAuth2Authorization(authToken, client, AuthGrantTypes.TOKEN_EXCHANGE);

        OAuth2AccessToken accessToken = auth2Authorization.getAccessToken().getToken();
        OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                .withToken(accessToken.getTokenValue())
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .refreshToken(auth2Authorization.getRefreshToken().getToken().getTokenValue())
                .scopes(accessToken.getScopes());

        Instant issuedAt = accessToken.getIssuedAt();
        if (issuedAt != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(issuedAt, accessToken.getExpiresAt()));
        }

        return builder.build();
    }
}
