package com.mcueen.auth.service.impl;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.provider.AuthenticationProviderHelper;
import com.mcueen.auth.controller.dto.AuthProviderDto;
import com.mcueen.auth.controller.dto.OAuthCallbackDto;
import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.AuthProviderRepository;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.AuthProviderService;
import com.mcueen.auth.service.oauth.OAuthProviderFactory;
import com.mcueen.auth.service.oauth.OAuthUserInfo;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import com.mcueen.auth.util.auth.AuthGrantTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
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
    private UserRepository userRepository;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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
    public OAuth2AccessTokenResponse handleOAuthCallback(OAuthCallbackDto callbackDto, String clientId, String clientSecret) {
        // Validate OAuth2 client
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        if (!passwordEncoder.matches(clientSecret, client.getClientSecret())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
        }

        // Get provider config from DB
        AuthProvider authProvider = authProviderRepository.findByName(callbackDto.getProvider())
                .orElseThrow(() -> new BadCredentialsException("Unsupported provider: " + callbackDto.getProvider()));

        // Exchange code for user info
        OAuthUserInfo oauthUser = oAuthProviderFactory.getProvider(callbackDto.getProvider())
                .exchangeCodeAndGetUserInfo(callbackDto.getCode(), callbackDto.getRedirectUri(), authProvider);

        if (!oauthUser.isEmailVerified()) {
            throw new BadCredentialsException(AuthErrorMessages.EMAIL_NOT_VERIFIED);
        }

        // Find or create user
        String provider = callbackDto.getProvider();
        User user = userRepository.findByOauthProviderAndOauthProviderId(provider, oauthUser.getProviderId())
                .or(() -> userRepository.findByEmail(oauthUser.getEmail()))
                .orElseGet(() -> createOAuthUser(oauthUser, provider));

        // Link account if needed
        if (user.getOauthProviderId() == null) {
            user.setOauthProvider(provider);
            user.setOauthProviderId(oauthUser.getProviderId());
            user.setAuthMethod(AuthConstants.AUTH_METHOD_BOTH);
            userRepository.save(user);
        }

        // Generate tokens
        ClientUserAuthenticationToken authToken = new ClientUserAuthenticationToken(
                user.getEmail(), null, clientId, clientSecret);

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

    private User createOAuthUser(OAuthUserInfo oauthUser, String provider) {
        User user = new User();
        user.setEmail(oauthUser.getEmail());
        user.setOauthProvider(provider);
        user.setOauthProviderId(oauthUser.getProviderId());
        user.setFirstname(oauthUser.getFirstName());
        user.setLastname(oauthUser.getLastName());
        user.setAuthMethod(AuthConstants.AUTH_METHOD_OAUTH);
        return userRepository.save(user);
    }
}
