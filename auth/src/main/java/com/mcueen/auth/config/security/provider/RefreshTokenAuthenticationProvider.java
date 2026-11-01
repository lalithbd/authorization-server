package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.RefreshTokenAuthenticationToken;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;

@Component
public class RefreshTokenAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private final OAuth2AuthorizationService auth2AuthorizationService;
    private final AuthenticationProviderHelper authenticationProviderHelper;

    public RefreshTokenAuthenticationProvider(OAuth2AuthorizationService auth2AuthorizationService,
                                              AuthenticationProviderHelper authenticationProviderHelper) {
        this.auth2AuthorizationService = auth2AuthorizationService;
        this.authenticationProviderHelper = authenticationProviderHelper;
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RefreshTokenAuthenticationToken token = (RefreshTokenAuthenticationToken) authentication;

        OAuth2Authorization oAuth2Authorization = auth2AuthorizationService.findByToken(token.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
        if (oAuth2Authorization != null) {
            OAuth2AccessToken refreshToken = oAuth2Authorization.getAccessToken().getToken();
            if (refreshToken != null && Objects.requireNonNull(refreshToken.getExpiresAt()).isAfter(Instant.now())) {
                OAuth2Authorization auth2Authorization = authenticationProviderHelper.getOAuth2Authorization(authentication, token.getRegisteredClient(), oAuth2Authorization.getAuthorizationGrantType());
                return new ClientUserAuthenticationToken(oAuth2Authorization.getPrincipalName(), null, auth2Authorization.getAccessToken(), auth2Authorization.getRefreshToken());
            }
        }
        throw new BadCredentialsException(AuthErrorMessages.INVALID_REFRESH_TOKEN);
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
