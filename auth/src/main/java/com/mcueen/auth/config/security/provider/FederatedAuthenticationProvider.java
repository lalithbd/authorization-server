package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.FederatedIdentityService;
import com.mcueen.auth.service.oauth.OAuthProviderFactory;
import com.mcueen.auth.service.oauth.OAuthUserInfo;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import com.mcueen.auth.util.auth.AuthGrantTypes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

@Component
public class FederatedAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private FederatedIdentityService federatedIdentityService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private OAuthProviderFactory oauthProviderFactory;

    @Autowired
    private AuthenticationProviderHelper authenticationProviderHelper;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ClientUserAuthenticationToken token = (ClientUserAuthenticationToken) authentication;
        String provider = (String) token.getDetails();
        
        if (AuthConstants.PROVIDER_EMAIL.equalsIgnoreCase(provider)) {
            return authenticateWithEmail(token);
        } else {
            return authenticateWithOAuth(token, provider);
        }
    }

    private Authentication authenticateWithEmail(ClientUserAuthenticationToken token) {
        RegisteredClient client = requireAuthenticatedClient(token);

        // Validate user credentials
        User user = userRepository.findByEmail(token.getName())
                .orElseThrow(() -> new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS));

        if (!passwordEncoder.matches(token.getCredentials().toString(), user.getPassword())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
        
        // Generate OAuth2 tokens
        OAuth2Authorization auth2Authorization = authenticationProviderHelper.getOAuth2Authorization(token, client, AuthGrantTypes.PASSWORD);
        return new ClientUserAuthenticationToken(token.getName(), client, auth2Authorization.getAccessToken(), auth2Authorization.getRefreshToken()
        );
    }

    private Authentication authenticateWithOAuth(ClientUserAuthenticationToken token, String provider) {
        RegisteredClient client = requireAuthenticatedClient(token);

        // Validate OAuth token against the provider's own configuration: the client id it must be
        // audience-bound to, and the issuer and keys it must be signed by.
        AuthProvider authProvider = federatedIdentityService.requireEnabledProvider(provider);

        String oauthToken = token.getCredentials().toString();
        OAuthUserInfo oauthUser = oauthProviderFactory.getProvider(provider).validateToken(oauthToken, authProvider);

        User user = federatedIdentityService.resolveUser(oauthUser, provider);

        // Carries the resolved principal into token generation; no credentials needed here.
        ClientUserAuthenticationToken authToken = new ClientUserAuthenticationToken(
                user.getEmail(),
                null,
                client.getClientId(),
                null
        );

        // Generate OAuth2 tokens with token exchange grant type
        OAuth2Authorization auth2Authorization = authenticationProviderHelper.getOAuth2Authorization(authToken, client, AuthGrantTypes.TOKEN_EXCHANGE);
        return new ClientUserAuthenticationToken(
            user.getEmail(), 
            client, 
            auth2Authorization.getAccessToken(), 
            auth2Authorization.getRefreshToken()
        );
    }

    /**
     * The client is authenticated by the filter before the token reaches this provider, which
     * attaches the verified {@link RegisteredClient}. A token without one never had its secret
     * checked, so it is rejected rather than silently trusted.
     */
    private RegisteredClient requireAuthenticatedClient(ClientUserAuthenticationToken token) {
        RegisteredClient client = token.getRegisteredClient();
        if (client == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        return client;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ClientUserAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
