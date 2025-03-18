package com.mcueen.auth.config.security.filter;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.service.JpaTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

public class CustomTokenHandler extends OncePerRequestFilter {

    private final JpaTokenService jpaTokenService;

    public CustomTokenHandler(JpaTokenService jpaTokenService) {
        this.jpaTokenService = jpaTokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String token = extractToken(request);
        if (token == null) {
            chain.doFilter(request, response);
            return;
        }
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            OAuth2TokenEntity auth2TokenEntity = jpaTokenService.findByToken(token);
            if (auth2TokenEntity != null && !auth2TokenEntity.isRevoked() && auth2TokenEntity.getExpiresAt().isBefore(Instant.now())) {
                ClientUserAuthenticationToken authentication = new ClientUserAuthenticationToken(token);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                List<GrantedAuthority> authorities = jpaTokenService.getAuthorities(auth2TokenEntity);
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
