package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.RefreshTokenAuthenticationToken;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.service.JpaTokenService;
import com.mcueen.auth.util.TokenType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class RefreshTokenAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    @Lazy
    private JpaTokenService jpaTokenService;

    @Autowired
    @Lazy
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private AuthenticationProviderHelper authenticationProviderHelper;


    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RefreshTokenAuthenticationToken RefreshTokenAuthenticationToken = (RefreshTokenAuthenticationToken) authentication;
        String password = RefreshTokenAuthenticationToken.getCredentials().toString();
        OAuth2TokenEntity refreshToken = jpaTokenService.findByTokenValueAndTokenType(password, TokenType.REFRESH);
        if (refreshToken != null && refreshToken.getTokenType().equals(TokenType.REFRESH) && !refreshToken.isRevoked() && !refreshToken.getExpiresAt().isBefore(Instant.now())) {
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
