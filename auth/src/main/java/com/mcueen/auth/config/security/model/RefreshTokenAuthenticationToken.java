package com.mcueen.auth.config.security.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
@Setter
public class RefreshTokenAuthenticationToken extends AbstractAuthenticationToken {

    private String refreshToken;

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
