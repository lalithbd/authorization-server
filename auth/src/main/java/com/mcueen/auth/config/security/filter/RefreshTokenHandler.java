package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.RefreshTokenAuthenticationToken;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.service.JpaTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class RefreshTokenHandler extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
    private final JpaTokenService jpaTokenService;

    public RefreshTokenHandler(AuthenticationManager authenticationManager, JpaTokenService jpaTokenService, OAuth2TokenGenerator<?> auth2TokenGenerator) {
        this.authenticationManager = authenticationManager;
        this.objectMapper = new ObjectMapper();
        this.jpaTokenService = jpaTokenService;
        this.tokenGenerator = auth2TokenGenerator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!"/auth/refresh".equals(request.getServletPath()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Map<String, String> loginRequest = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {});
            String refreshTokenString = loginRequest.get("refreshToken");
            ClientUserAuthenticationToken authentication = (ClientUserAuthenticationToken) authenticationManager.authenticate(
                    new RefreshTokenAuthenticationToken(null, refreshTokenString));

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)  // Requesting an access token
                    .principal(authentication)  // Authenticated user
                    .registeredClient(authentication.getRegisteredClient())  // OAuth2 client details
                    .authorizedScopes(Set.of("read", "write"))  // Define scopes
                    .build();
            OAuth2Token oAuth2Token = tokenGenerator.generate(tokenContext);
            tokenContext = DefaultOAuth2TokenContext.builder()
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)  // Requesting an access token
                    .principal(authentication)  // Authenticated user
                    .registeredClient(authentication.getRegisteredClient())  // OAuth2 client details
                    .authorizedScopes(Set.of("read", "write"))  // Define scopes
                    .build();
            OAuth2Token refreshToken = tokenGenerator.generate(tokenContext);
            OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                    .withToken(oAuth2Token != null ? oAuth2Token.getTokenValue() : null)
                    .tokenType(OAuth2AccessToken.TokenType.BEARER)
                    .refreshToken(refreshToken != null ? refreshToken.getTokenValue() : null)
                    .scopes(tokenContext.getAuthorizedScopes())
                    .expiresIn(ChronoUnit.SECONDS.between(Objects.requireNonNull(oAuth2Token != null ? oAuth2Token.getIssuedAt() : null), oAuth2Token.getExpiresAt()));
            jpaTokenService.saveToken(oAuth2Token, refreshToken, authentication.getRegisteredClient(), authentication.getName());

            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(builder.build(), null, httpResponse);


        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Invalid username or password\"}");
        }
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return (header != null && header.startsWith("Bearer ")) ? header.substring(7) : null;
    }
}
