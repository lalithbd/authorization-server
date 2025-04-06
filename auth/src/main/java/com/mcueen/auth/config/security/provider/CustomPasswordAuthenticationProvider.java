package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.util.Base64;

@Component
public class CustomPasswordAuthenticationProvider extends DaoAuthenticationProvider {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private AuthenticationProviderHelper authenticationProviderHelper;

    public CustomPasswordAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        super.setUserDetailsService(userDetailsService);
        super.setPasswordEncoder(passwordEncoder);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ClientUserAuthenticationToken clientUserAuthenticationToken = (ClientUserAuthenticationToken) authentication;
        String username = clientUserAuthenticationToken.getName();
        String password = clientUserAuthenticationToken.getCredentials().toString();
        String clientId = clientUserAuthenticationToken.getClientId();
        String clientSecret = clientUserAuthenticationToken.getClientSecret();
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BadCredentialsException("Invalid client");
        }
        if (!super.getPasswordEncoder().matches(clientSecret, client.getClientSecret())) {
            throw new BadCredentialsException("Invalid client credentials");
        }
        UserDetails userDetails = super.getUserDetailsService().loadUserByUsername(username);
        if (userDetails != null && super.getPasswordEncoder().matches(password, userDetails.getPassword())) {
            OAuth2Authorization auth2Authorization = authenticationProviderHelper.getOAuth2Authorization(authentication, client);
            return new ClientUserAuthenticationToken(username, client, auth2Authorization.getAccessToken(), auth2Authorization.getRefreshToken());
        }

        throw new BadCredentialsException("Invalid credentials");
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) {

        if (authentication.getCredentials() == null) {

            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
                            "Invalid credentials provided. Please check your username and password"));
        }

        String presentedPassword = new String(Base64.getUrlDecoder().decode(authentication.getCredentials().toString()));

        if (!this.getPasswordEncoder().matches(presentedPassword, userDetails.getPassword())) {
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
                            "Invalid credentials provided. Please check your username and password"));
        }
    }


}
