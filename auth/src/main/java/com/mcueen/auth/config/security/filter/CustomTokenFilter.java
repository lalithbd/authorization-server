package com.mcueen.auth.config.security.filter;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.CustomOAuth2AuthorizationService;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

@Component
public class CustomTokenFilter extends OncePerRequestFilter {

    @Autowired
    private CustomOAuth2AuthorizationService oAuth2AuthorizationService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String token = extractToken(request);
        if (token == null) {
            chain.doFilter(request, response);
            return;
        }
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            OAuth2TokenEntity auth2TokenEntity = oAuth2AuthorizationService.findByTokenValueAndTokenType(token, OAuth2TokenType.ACCESS_TOKEN);
            if (auth2TokenEntity != null && !auth2TokenEntity.isRevoked() && !auth2TokenEntity.getExpiresAt().isBefore(Instant.now())) {
                ClientUserAuthenticationToken authentication = new ClientUserAuthenticationToken(token);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return (header != null && header.startsWith("Bearer ")) ? header.substring(7) : null;
    }
}
