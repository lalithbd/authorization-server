package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.RefreshTokenAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

@Component
public class RefreshTokenAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private OAuth2AuthorizationService auth2AuthorizationService;

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RefreshTokenAuthenticationToken clientUserAuthenticationToken = (RefreshTokenAuthenticationToken) authentication;

        OAuth2Authorization oAuth2Authorization = auth2AuthorizationService.findByToken(clientUserAuthenticationToken.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
        if (oAuth2Authorization != null) {
            OAuth2AccessToken refreshToken = oAuth2Authorization.getAccessToken().getToken();
            if (refreshToken != null && Objects.requireNonNull(refreshToken.getExpiresAt()).isAfter(Instant.now())) {
                return new ClientUserAuthenticationToken(oAuth2Authorization.getPrincipalName(), null, null, oAuth2Authorization.getRegisteredClientId());
            }
        }
        throw new BadCredentialsException("Invalid refresh token");
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
