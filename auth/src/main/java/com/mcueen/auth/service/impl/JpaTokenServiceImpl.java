package com.mcueen.auth.service.impl;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.model.user.UserRole;
import com.mcueen.auth.repository.OAuth2TokenRepository;
import com.mcueen.auth.service.JpaTokenService;
import com.mcueen.auth.service.RolePermissionService;
import com.mcueen.auth.service.UserService;
import com.mcueen.auth.util.TokenType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
public class JpaTokenServiceImpl implements JpaTokenService {

    @Autowired
    private OAuth2TokenRepository tokenRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private RolePermissionService rolePermissionService;

    @Override
    @Transactional
    public void saveToken(OAuth2TokenEntity token) {
        OAuth2TokenEntity tokenEntity = OAuth2TokenEntity.builder().build();
        tokenEntity.setIssuedAt(token.getIssuedAt());
        tokenEntity.setExpiresAt(token.getExpiresAt());
        tokenRepository.save(tokenEntity);
    }

    @Override
    @Transactional
    public void saveToken(OAuth2AccessToken accessToken, OAuth2Token refreshToken, RegisteredClient registeredClient, String name) {
        tokenRepository.deleteAllByEmail(name);
        OAuth2TokenEntity accessTokenEntity = OAuth2TokenEntity.builder()
                .tokenValue(accessToken.getTokenValue())
                .tokenType(TokenType.ACCESS)
                .clientId(registeredClient.getClientId())
                .expiresAt(accessToken.getExpiresAt())
                .issuedAt(accessToken.getIssuedAt())
                .scopes(accessToken.getScopes().stream().toList())
                .email(name).build();
        OAuth2TokenEntity refreshTokenEntity = OAuth2TokenEntity.builder()
                .tokenValue(refreshToken.getTokenValue())
                .tokenType(TokenType.REFRESH)
                .clientId(registeredClient.getClientId())
                .expiresAt(refreshToken.getExpiresAt())
                .issuedAt(refreshToken.getIssuedAt())
                .email(name).build();
        tokenRepository.save(accessTokenEntity);
        tokenRepository.save(refreshTokenEntity);
    }

    @Override
    public List<GrantedAuthority> getAuthorities(OAuth2TokenEntity auth2TokenEntity) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        if (auth2TokenEntity != null) {
            String email = auth2TokenEntity.getEmail();
            if (email != null) {
                User user = userService.findByEmail(email);
                if (user != null) {
                    List<UserRole> userRoles = rolePermissionService.getUserRolesByUserId(user.getId());
                    List<SimpleGrantedAuthority> permissions = userRoles.stream()
                            .flatMap(userRole -> rolePermissionService.getRolePermissionsByRoleId(userRole.getRole().getId()).stream())
                            .toList().stream().map(rolePermission -> new SimpleGrantedAuthority("PERMISSION_" + rolePermission.getPermission().getName())).toList();
                    grantedAuthorities.addAll(permissions);
                }
            }

            List<String> scopes = auth2TokenEntity.getScopes();
            if (!CollectionUtils.isEmpty(scopes)) {
                List<GrantedAuthority> scopeAuthorities = scopes.stream()
                        .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                        .collect(Collectors.toList());

                grantedAuthorities.addAll(scopeAuthorities);
            }

        }
        return grantedAuthorities;
    }

    @Override
    public OAuth2TokenEntity findByTokenValueAndTokenType(String token, TokenType tokenType) {
        return tokenRepository.findByTokenValueAndTokenType(token, tokenType);
    }
}
