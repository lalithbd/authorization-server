package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.service.impl.OAuth2AuthorizationServiceImpl;
import com.mcueen.auth.util.TokenType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class TokenIntrospectionHandler extends OncePerRequestFilter {

    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    public TokenIntrospectionHandler(OAuth2AuthorizationServiceImpl oAuth2AuthorizationService) {
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!"/oauth2/introspect".equals(request.getRequestURI()) || !"POST".equals(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = request.getParameter("token");
        OAuth2TokenEntity tokenEntity = oAuth2AuthorizationService.findEntityByToken(token, TokenType.ACCESS);
        Map<String, Object> responseBody = new HashMap<>();
        if (tokenEntity == null || Objects.requireNonNull(tokenEntity.getExpiresAt()).isBefore(Instant.now())) {
            responseBody.put("active", false);
        } else {
            responseBody.put("active", true);
            responseBody.put("client_id", tokenEntity.getClientId());
            responseBody.put("exp", tokenEntity.getExpiresAt().getEpochSecond());
            responseBody.put("iat", Objects.requireNonNull(tokenEntity.getIssuedAt()).getEpochSecond());

            if (tokenEntity.getEmail() != null) {
                responseBody.put("sub", tokenEntity.getEmail());
            } else {
                RegisteredClient registeredClient = registeredClientRepository.findById(tokenEntity.getClientId());
                if (registeredClient != null) {
                    responseBody.put("sub", registeredClient.getClientId());
                }
            }

            List<GrantedAuthority> authorities = oAuth2AuthorizationService.getAuthorities(tokenEntity);
            List<String> permissions = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
            responseBody.put("authorities", permissions);
        }

        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(responseBody));
    }
}