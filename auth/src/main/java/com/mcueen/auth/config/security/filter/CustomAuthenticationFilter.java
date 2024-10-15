package com.mcueen.auth.config.security.filter;

import com.mcueen.auth.config.security.converter.PasswordAuthenticationConverter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(value = Ordered.HIGHEST_PRECEDENCE)
public class CustomAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private PasswordAuthenticationConverter passwordAuthenticationConverter;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        super("/token", authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        return new PasswordAuthenticationConverter(super.getAuthenticationManager()).convert(request);
    }

}
