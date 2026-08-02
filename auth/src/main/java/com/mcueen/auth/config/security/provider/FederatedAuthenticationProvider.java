package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.UserRepository;
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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
public class FederatedAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private OAuthProviderFactory oauthProviderFactory;
    
    @Autowired
    private RegisteredClientRepository registeredClientRepository;
    
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
        // Validate client credentials
        RegisteredClient client = registeredClientRepository.findByClientId(token.getClientId());
        if (client == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        if (!passwordEncoder.matches(token.getClientSecret(), client.getClientSecret())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
        }
        
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
        // Validate client credentials
        RegisteredClient client = registeredClientRepository.findByClientId(token.getClientId());
        if (client == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        if (!passwordEncoder.matches(token.getClientSecret(), client.getClientSecret())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
        }
        
        // Validate OAuth token
        String oauthToken = token.getCredentials().toString();
        OAuthUserInfo oauthUser = oauthProviderFactory.getProvider(provider).validateToken(oauthToken);

        if (!oauthUser.isEmailVerified()) {
            throw new BadCredentialsException(AuthErrorMessages.EMAIL_NOT_VERIFIED);
        }

        User user = userRepository.findByOauthProviderAndOauthProviderId(provider, oauthUser.getProviderId())
                .or(() -> userRepository.findByEmail(oauthUser.getEmail()))
                .orElseGet(() -> createOAuthUser(oauthUser, provider));

        if (user.getOauthProviderId() == null) {
            user.setOauthProvider(provider);
            user.setOauthProviderId(oauthUser.getProviderId());
            user.setAuthMethod(AuthConstants.AUTH_METHOD_BOTH);
            userRepository.save(user);
        }

        ClientUserAuthenticationToken authToken = new ClientUserAuthenticationToken(
                user.getEmail(), 
                null, 
                token.getClientId(), 
                token.getClientSecret()
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

    @Override
    public boolean supports(Class<?> authentication) {
        return ClientUserAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
