package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientAuthenticator;
import com.mcueen.auth.controller.dto.OAuthCallbackDto;
import com.mcueen.auth.config.security.model.UnAuthorizedResponse;
import com.mcueen.auth.service.AuthProviderService;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthEndpoints;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class OAuthCallbackHandler extends OncePerRequestFilter {

    private final AuthProviderService authProviderService;
    private final ObjectMapper objectMapper;
    private final ClientAuthenticator clientAuthenticator;

    public OAuthCallbackHandler(AuthProviderService authProviderService, ObjectMapper objectMapper, ClientAuthenticator clientAuthenticator) {
        this.authProviderService = authProviderService;
        this.objectMapper = objectMapper;
        this.clientAuthenticator = clientAuthenticator;
    }

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!AuthEndpoints.OAUTH_CALLBACK.equals(request.getServletPath()) || !AuthEndpoints.POST.equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            OAuthCallbackDto callbackDto = objectMapper.readValue(request.getInputStream(), OAuthCallbackDto.class);

            // Extract client credentials from Basic auth header
            RegisteredClient client = clientAuthenticator.authenticateClient(request);

            OAuth2AccessTokenResponse tokenResponse = authProviderService.handleOAuthCallback(callbackDto, client);

            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(tokenResponse, null, httpResponse);

        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            UnAuthorizedResponse errorResponse = UnAuthorizedResponse.builder()
                    .status(String.valueOf(HttpServletResponse.SC_UNAUTHORIZED))
                    .message(e.getMessage())
                    .build();
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        }
    }
}
