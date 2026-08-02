package com.mcueen.auth.service.impl;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.model.user.UserRole;
import com.mcueen.auth.repository.OAuth2TokenRepository;
import com.mcueen.auth.service.RolePermissionService;
import com.mcueen.auth.service.UserService;
import com.mcueen.auth.util.TokenType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional(readOnly = true)
public class OAuth2AuthorizationServiceImpl implements OAuth2AuthorizationService {

    @Autowired
    private OAuth2TokenRepository tokenRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private RolePermissionService rolePermissionService;

    @Autowired
    private JpaRegisteredClientService registeredClientRepository;


    public List<GrantedAuthority> getAuthorities(OAuth2TokenEntity tokenEntity) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        if (tokenEntity != null) {
            String email = tokenEntity.getEmail();
            if (email != null) {
                // User-based permissions
                User user = userService.findByEmail(email);
                if (user != null) {
                    List<UserRole> userRoles = rolePermissionService.getUserRolesByUserId(user.getId());
                    List<SimpleGrantedAuthority> permissions = userRoles.stream()
                            .flatMap(userRole -> rolePermissionService.getRolePermissionsByRoleId(userRole.getRole().getId()).stream())
                            .toList().stream().map(rolePermission -> new SimpleGrantedAuthority("PERMISSION_" + rolePermission.getPermission().getName())).toList();
                    grantedAuthorities.addAll(permissions);
                }
            } else {
                // Client-only permissions (client credentials flow)
                String clientId = tokenEntity.getClientId();
                RegisteredClient client = registeredClientRepository.findById(tokenEntity.getClientId());
                // Add predefined client permissions based on clientId
                if ("admin-client".equals(clientId)) {
                    grantedAuthorities.add(new SimpleGrantedAuthority("PERMISSION_admin_read"));
                    grantedAuthorities.add(new SimpleGrantedAuthority("PERMISSION_admin_write"));
                } else if ("read-client".equals(clientId)) {
                    grantedAuthorities.add(new SimpleGrantedAuthority("PERMISSION_read_only"));
                }
            }

            Set<String> scopes = tokenEntity.getScopes();
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
    @Transactional
    public void save(OAuth2Authorization authorization) {
        String clientId = authorization.getRegisteredClientId();
        String principalName = authorization.getPrincipalName();
        String userEmail = principalName.equals(clientId) ? null : principalName;
        OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
        OAuth2TokenEntity accessTokenEntity = OAuth2TokenEntity.builder()
                .tokenValue(accessToken.getTokenValue())
                .tokenType(TokenType.ACCESS.toString())
                .clientId(clientId)
                .expiresAt(accessToken.getExpiresAt())
                .issuedAt(accessToken.getIssuedAt())
                .authorizationId(authorization.getId())
                .scopes(authorization.getAuthorizedScopes())
                .email(userEmail)
                .grantType(authorization.getAuthorizationGrantType().getValue()).build();
        if (authorization.getRefreshToken() != null) {
            OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
            OAuth2TokenEntity refreshTokenEntity = OAuth2TokenEntity.builder()
                    .tokenValue(refreshToken.getTokenValue())
                    .tokenType(TokenType.REFRESH.toString())
                    .clientId(clientId)
                    .expiresAt(refreshToken.getExpiresAt())
                    .issuedAt(refreshToken.getIssuedAt())
                    .authorizationId(authorization.getId())
                    .email(userEmail)
                    .grantType(authorization.getAuthorizationGrantType().getValue()).build();
            tokenRepository.save(refreshTokenEntity);
        }
        tokenRepository.save(accessTokenEntity);
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        tokenRepository.deleteById(Long.valueOf(authorization.getId()));
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType oAuth2TokenType) {
        if (oAuth2TokenType == null) {
            return null;
        }
        TokenType tokenType = oAuth2TokenType.equals(OAuth2TokenType.ACCESS_TOKEN) ? TokenType.ACCESS : TokenType.REFRESH;
        OAuth2TokenEntity tokenEntity = tokenRepository.findByTokenValueAndTokenType(token, tokenType.toString()).orElse(null);
        if (tokenEntity == null) {
            return null;
        }
        OAuth2Token auth2Token;
        if (oAuth2TokenType.equals(OAuth2TokenType.ACCESS_TOKEN)) {
            auth2Token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenEntity.getTokenValue(), tokenEntity.getIssuedAt(), tokenEntity.getExpiresAt());
        } else {
            auth2Token = new OAuth2RefreshToken(tokenEntity.getTokenValue(), tokenEntity.getIssuedAt(), tokenEntity.getExpiresAt());
        }
        RegisteredClient registeredClient = registeredClientRepository.findById(tokenEntity.getClientId());
        if (registeredClient == null) {
            return null;
        }
        return OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .token(auth2Token)
                .authorizationGrantType(new AuthorizationGrantType(tokenEntity.getGrantType()))
                .principalName(tokenEntity.getEmail())
                .build();
    }


    public OAuth2TokenEntity findEntityByToken(String token, TokenType tokenType) {
        return tokenRepository.findByTokenValueAndTokenType(token, tokenType.toString()).orElse(null);
    }
}
