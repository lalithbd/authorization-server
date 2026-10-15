package com.mcueen.auth.config.security.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.Collection;

@Getter
@Setter
public class RefreshTokenAuthenticationToken extends AbstractAuthenticationToken {

    private String refreshToken;

    /**
     * The client the caller claims to be. Identified from {@code client_id} only, so it binds the
     * request to a client without proving the caller's identity.
     */
    private RegisteredClient registeredClient;

    public RefreshTokenAuthenticationToken(Collection<? extends GrantedAuthority> authorities, String refreshToken) {
        super(authorities);
        this.refreshToken = refreshToken;
    }

    @Override
    public Object getCredentials() {
        return refreshToken;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }


}
