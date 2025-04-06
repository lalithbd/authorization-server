package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.CustomOAuth2AuthorizationService;
import com.mcueen.auth.config.security.model.RefreshTokenAuthenticationToken;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class RefreshTokenAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    @Lazy
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private AuthenticationProviderHelper authenticationProviderHelper;

    @Autowired
    private CustomOAuth2AuthorizationService oAuth2AuthorizationService;


    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RefreshTokenAuthenticationToken RefreshTokenAuthenticationToken = (RefreshTokenAuthenticationToken) authentication;
        String password = RefreshTokenAuthenticationToken.getCredentials().toString();
        OAuth2TokenEntity refreshToken = oAuth2AuthorizationService.findByTokenValueAndTokenType(password, OAuth2TokenType.REFRESH_TOKEN);
        if (refreshToken != null && !refreshToken.isRevoked() && !refreshToken.getExpiresAt().isBefore(Instant.now())) {
            RegisteredClient client = registeredClientRepository.findByClientId(refreshToken.getClientId());
            OAuth2Authorization auth2Authorization = authenticationProviderHelper.getOAuth2Authorization(authentication, client);
            return new ClientUserAuthenticationToken(refreshToken.getEmail(), client, auth2Authorization.getAccessToken(), auth2Authorization.getRefreshToken());
        }

        throw new BadCredentialsException("Invalid credentials");
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
