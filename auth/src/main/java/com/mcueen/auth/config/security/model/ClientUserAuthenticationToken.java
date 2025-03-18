package com.mcueen.auth.config.security.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Collection;

@Getter
@Setter
public class ClientUserAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private String clientId;
    private String clientSecret;
    private RegisteredClient registeredClient;

    public ClientUserAuthenticationToken(Object principal, Object credentials, String clientId, String clientSecret) {
        super(principal, credentials);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public ClientUserAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, RegisteredClient registeredClient) {
        super(principal, credentials, authorities);
        this.registeredClient = registeredClient;
    }

    public ClientUserAuthenticationToken(Object principal) {
        super(principal, null, null);
    }
}
