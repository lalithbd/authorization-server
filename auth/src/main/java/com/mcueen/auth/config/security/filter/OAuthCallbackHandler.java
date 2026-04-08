package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.controller.dto.OAuthCallbackDto;
import com.mcueen.auth.service.AuthProviderService;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthEndpoints;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

@Component
public class OAuthCallbackHandler extends OncePerRequestFilter {

    @Autowired
    private AuthProviderService authProviderService;

    @Autowired
    private ObjectMapper objectMapper;

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!AuthEndpoints.OAUTH_CALLBACK.equals(request.getServletPath()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            OAuthCallbackDto callbackDto = objectMapper.readValue(request.getInputStream(), OAuthCallbackDto.class);

            // Extract client credentials from Basic auth header
            String authHeader = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);
            if (authHeader == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS_JSON);
                return;
            }
            String base64Credentials = authHeader.substring(AuthConstants.BASIC_PREFIX_LENGTH);
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            String[] parts = credentials.split(":", 2);

            OAuth2AccessTokenResponse tokenResponse = authProviderService.handleOAuthCallback(callbackDto, parts[0], parts[1]);

            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(tokenResponse, null, httpResponse);

        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(AuthErrorMessages.INVALID_CREDENTIALS_JSON);
        }
    }
}
