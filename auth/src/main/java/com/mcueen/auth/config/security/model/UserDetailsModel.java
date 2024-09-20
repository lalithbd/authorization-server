package com.mcueen.auth.config.security.model;

import com.mcueen.auth.model.user.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class UserDetailsModel implements UserDetails {

    private String username;
    private String password;

    private List<SimpleGrantedAuthority> authorities;

    public UserDetailsModel(User user) {
        this.username = user.getEmail();
        this.password = user.getPassword();
        this.authorities = user.getUserRoles().stream().flatMap(userRole ->
                userRole.getRole().getRolePermissions().stream().map(rolePermission ->
                        rolePermission.getPermission().getName())).map(SimpleGrantedAuthority::new).toList();
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }
}
