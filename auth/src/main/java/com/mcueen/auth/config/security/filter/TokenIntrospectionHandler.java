package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.service.impl.OAuth2AuthorizationServiceImpl;
import com.mcueen.auth.util.TokenType;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthEndpoints;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * RFC 7662 token introspection at {@link AuthEndpoints#INTROSPECT}.
 * <p>
 * The caller must authenticate as a registered client (client_secret_basic or
 * client_secret_post), per RFC 7662 section 2.1.
 * <p>
 * Deliberately not a bean. Spring Boot auto-registers every {@link jakarta.servlet.Filter} bean
 * against {@code /*}, which would run this outside the security chain. It is constructed in
 * {@code AuthorizationServerConfig} and added to the chain there instead.
 */
public class TokenIntrospectionHandler extends OncePerRequestFilter {

    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

    private final ObjectMapper objectMapper;

    private final ClientAuthenticator clientAuthenticator;

    public TokenIntrospectionHandler(OAuth2AuthorizationServiceImpl oAuth2AuthorizationService,
                                     ObjectMapper objectMapper,
                                     ClientAuthenticator clientAuthenticator) {
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
        this.objectMapper = objectMapper;
        this.clientAuthenticator = clientAuthenticator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (!AuthEndpoints.INTROSPECT.equals(request.getServletPath()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        try {
            clientAuthenticator.authenticate(request);
        } catch (AuthenticationException e) {
            writeError(response, HttpServletResponse.SC_UNAUTHORIZED, AuthErrorMessages.ERROR_INVALID_CLIENT, e.getMessage());
            return;
        }

        String token = request.getParameter(AuthConstants.FIELD_TOKEN);
        if (token == null || token.isBlank()) {
            writeError(response, HttpServletResponse.SC_BAD_REQUEST, AuthErrorMessages.ERROR_INVALID_REQUEST,
                    AuthErrorMessages.MISSING_TOKEN_PARAMETER);
            return;
        }

        OAuth2TokenEntity tokenEntity = oAuth2AuthorizationService.findEntityByToken(token, TokenType.ACCESS);
        objectMapper.writeValue(response.getWriter(), introspect(tokenEntity));
    }

    private Map<String, Object> introspect(OAuth2TokenEntity tokenEntity) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (!isActive(tokenEntity)) {
            body.put("active", false);
            return body;
        }

        body.put("active", true);
        body.put("client_id", tokenEntity.getClientId());
        body.put("token_type", "Bearer");
        body.put("exp", tokenEntity.getExpiresAt().getEpochSecond());

        Instant issuedAt = tokenEntity.getIssuedAt();
        if (issuedAt != null) {
            body.put("iat", issuedAt.getEpochSecond());
        }

        String subject = tokenEntity.getEmail() != null ? tokenEntity.getEmail() : tokenEntity.getClientId();
        body.put("sub", subject);
        if (tokenEntity.getEmail() != null) {
            body.put("username", tokenEntity.getEmail());
        }

        Set<String> scopes = tokenEntity.getScopes();
        if (scopes != null && !scopes.isEmpty()) {
            body.put("scope", String.join(" ", scopes));
        }

        List<String> authorities = oAuth2AuthorizationService.getAuthorities(tokenEntity).stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        if (!authorities.isEmpty()) {
            body.put("authorities", authorities);
        }

        return body;
    }

    private boolean isActive(OAuth2TokenEntity tokenEntity) {
        return tokenEntity != null
                && !tokenEntity.isRevoked()
                && tokenEntity.getExpiresAt() != null
                && tokenEntity.getExpiresAt().isAfter(Instant.now());
    }

    private void writeError(HttpServletResponse response, int status, String error, String description) throws IOException {
        response.setStatus(status);
        if (status == HttpServletResponse.SC_UNAUTHORIZED) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"introspection\"");
        }
        Map<String, Object> body = new HashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        objectMapper.writeValue(response.getWriter(), body);
    }
}
