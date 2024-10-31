package com.mcueen.auth.config.security.filter;

import com.mcueen.auth.config.security.converter.PasswordAuthenticationConverter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class CustomAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationConverter authenticationConverter;
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationConverter = new PasswordAuthenticationConverter(authenticationManager);
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = authenticationConverter.convert(request);
        if (authentication != null) {
            try {
                Authentication authResult = authenticationManager.authenticate(authentication);
                SecurityContextHolder.getContext().setAuthentication(authResult);
            } catch (AuthenticationException e) {
                // Handle authentication failure (e.g., return 401 Unauthorized)
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
                return;
            }
        } else {
            // If authentication is null, send a 400 Bad Request response
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing authentication parameters");
            return;
        }

        filterChain.doFilter(request, response); // Continue the filter chain
    }
}
