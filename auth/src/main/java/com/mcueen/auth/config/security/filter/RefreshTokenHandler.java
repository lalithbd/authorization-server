package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.RefreshTokenAuthenticationToken;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthEndpoints;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Deliberately not a bean. Spring Boot auto-registers every {@link jakarta.servlet.Filter} bean
 * against {@code /*}, which would run this outside the security chain. It is constructed in
 * {@code AuthorizationServerConfig} and added to the chain there instead.
 */
public class RefreshTokenHandler extends OncePerRequestFilter {

    private final AuthenticationFilterHelper authenticationFilterHelper;

    private final ObjectMapper objectMapper;

    private final ClientAuthenticator clientAuthenticator;

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

    public RefreshTokenHandler(AuthenticationFilterHelper authenticationFilterHelper,
                               ObjectMapper objectMapper,
                               ClientAuthenticator clientAuthenticator) {
        this.authenticationFilterHelper = authenticationFilterHelper;
        this.objectMapper = objectMapper;
        this.clientAuthenticator = clientAuthenticator;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!AuthEndpoints.REFRESH.equals(request.getServletPath()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Map<String, String> loginRequest = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {});
            String refreshTokenString = loginRequest.get(AuthConstants.FIELD_REFRESH_TOKEN);

            // client_id only: the caller here is a public client that cannot hold a secret, so this
            // identifies the client rather than authenticating it. It stops one client refreshing
            // another's token; it does not make a stolen refresh token unusable, because a client id
            // is public. A confidential caller should be sent through clientAuthenticator.authenticate.
            RegisteredClient client = clientAuthenticator.identifyClient(
                    loginRequest.get(AuthConstants.FIELD_CLIENT_ID));

            RefreshTokenAuthenticationToken authToken =
                    new RefreshTokenAuthenticationToken(null, refreshTokenString);
            authToken.setRegisteredClient(client);

            OAuth2AccessTokenResponse auth2AccessTokenResponse =
                    authenticationFilterHelper.buildOAuth2AccessTokenResponse(authToken);
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(auth2AccessTokenResponse, null, httpResponse);


        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(AuthErrorMessages.INVALID_CREDENTIALS_JSON);
        }
    }
}
