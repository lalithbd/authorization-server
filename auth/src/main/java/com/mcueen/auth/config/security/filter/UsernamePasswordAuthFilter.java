package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Slf4j
@Component
public class UsernamePasswordAuthFilter extends OncePerRequestFilter {

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

    @Autowired
    private AuthenticationFilterHelper authenticationFilterHelper;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!"/auth/login".equals(request.getServletPath()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Map<String, String> loginRequest = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {
            });
            String username = loginRequest.get("username");
            String password = loginRequest.get("password");
            String authHeader = request.getHeader("Authorization");
            if (authHeader == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Invalid Client credentials\"}");
                return;
            }
            String base64Credentials = authHeader.substring(6);
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            String[] parts = credentials.split(":", 2);
            OAuth2AccessTokenResponse oAuth2AccessTokenResponse = authenticationFilterHelper.buildOAuth2AccessTokenResponse(new ClientUserAuthenticationToken(username, password, parts[0], parts[1]));
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(oAuth2AccessTokenResponse, null, httpResponse);


        } catch (NullPointerException | AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Invalid username or password\"}");
        }
    }
}
