package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.AuthProviderRepository;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.oauth.OAuthProviderFactory;
import com.mcueen.auth.service.oauth.OAuthUserInfo;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import com.mcueen.auth.util.auth.AuthGrantTypes;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.stereotype.Component;

@Component
public class FederatedAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final AuthProviderRepository authProviderRepository;
    private final PasswordEncoder passwordEncoder;
    private final OAuthProviderFactory oauthProviderFactory;
    private final AuthenticationProviderHelper authenticationProviderHelper;

    public FederatedAuthenticationProvider(UserRepository userRepository,
                                           AuthProviderRepository authProviderRepository,
                                           PasswordEncoder passwordEncoder,
                                           OAuthProviderFactory oauthProviderFactory,
                                           AuthenticationProviderHelper authenticationProviderHelper) {
        this.userRepository = userRepository;
        this.authProviderRepository = authProviderRepository;
        this.passwordEncoder = passwordEncoder;
        this.oauthProviderFactory = oauthProviderFactory;
        this.authenticationProviderHelper = authenticationProviderHelper;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ClientUserAuthenticationToken token = (ClientUserAuthenticationToken) authentication;
        if (!(token.getDetails() instanceof String provider) || provider.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
        return AuthConstants.PROVIDER_EMAIL.equalsIgnoreCase(provider)
                ? authenticateWithEmail(token) : authenticateWithOAuth(token, provider);
    }

    private Authentication authenticateWithEmail(ClientUserAuthenticationToken token) {
        if (!(token.getPrincipal() instanceof String username) || username.isBlank()
                || !(token.getCredentials() instanceof String password) || password.isEmpty()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS));

        if (user.getPassword() == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }

        ClientUserAuthenticationToken verifiedToken = new ClientUserAuthenticationToken(user.getEmail(), null, token.getClientId());
        verifiedToken.setRegisteredClient(token.getRegisteredClient());
        OAuth2Authorization auth2Authorization = authenticationProviderHelper
                .getOAuth2Authorization(verifiedToken, token.getRegisteredClient(), AuthGrantTypes.PASSWORD);
        return new ClientUserAuthenticationToken(
            user.getEmail(), null, auth2Authorization.getAccessToken(), auth2Authorization.getRefreshToken());
    }

    private Authentication authenticateWithOAuth(ClientUserAuthenticationToken token, String provider) {
        if (!(token.getCredentials() instanceof String providerToken) || providerToken.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
        if (!AuthConstants.PROVIDER_GOOGLE.equals(provider) && !AuthConstants.PROVIDER_MICROSOFT.equals(provider)) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
        AuthProvider config = authProviderRepository.findByName(provider)
                .filter(AuthProvider::isEnabled)
                .orElseThrow(() -> new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS));
        OAuthUserInfo oauthUser = oauthProviderFactory.getProvider(provider).validateToken(providerToken, config);
        if (oauthUser.getProviderId() == null || oauthUser.getProviderId().isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }

        User user = userRepository.findByOauthProviderAndOauthProviderId(provider, oauthUser.getProviderId())
                .orElseGet(() -> createOAuthUser(oauthUser, provider));
        if (user.getEmail() == null || user.getEmail().isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
        ClientUserAuthenticationToken verifiedToken = new ClientUserAuthenticationToken(user.getEmail(), null, token.getClientId());
        verifiedToken.setRegisteredClient(token.getRegisteredClient());
        OAuth2Authorization authorization = authenticationProviderHelper
                .getOAuth2Authorization(verifiedToken, token.getRegisteredClient(), AuthGrantTypes.TOKEN_EXCHANGE);
        return new ClientUserAuthenticationToken(
                user.getEmail(), null, authorization.getAccessToken(), authorization.getRefreshToken());
    }

    private User createOAuthUser(OAuthUserInfo oauthUser, String provider) {
        if (!oauthUser.isEmailVerified() || oauthUser.getEmail() == null || oauthUser.getEmail().isBlank()
                || userRepository.findByEmail(oauthUser.getEmail()).isPresent()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
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
