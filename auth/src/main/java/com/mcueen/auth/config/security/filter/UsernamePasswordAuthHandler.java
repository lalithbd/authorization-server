package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientAuthenticator;
import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.UnAuthorizedResponse;
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
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;

public class UsernamePasswordAuthHandler extends OncePerRequestFilter {

    private final AuthenticationFilterHelper authenticationFilterHelper;
    private final ObjectMapper objectMapper;
    private final ClientAuthenticator clientAuthenticator;

    public UsernamePasswordAuthHandler(AuthenticationFilterHelper authenticationFilterHelper,
                                       ObjectMapper objectMapper, ClientAuthenticator clientAuthenticator) {
        this.authenticationFilterHelper = authenticationFilterHelper;
        this.objectMapper = objectMapper;
        this.clientAuthenticator = clientAuthenticator;
    }

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!AuthEndpoints.LOGIN.equals(request.getServletPath()) || !AuthEndpoints.POST.equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Map<String, String> loginRequest = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {
            });
            String requestedProvider = loginRequest.getOrDefault(AuthConstants.FIELD_PROVIDER, AuthConstants.PROVIDER_EMAIL);
            if (requestedProvider == null) {
                throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
            }
            String provider = requestedProvider.toLowerCase(Locale.ROOT);
            boolean passwordLogin = AuthConstants.PROVIDER_EMAIL.equals(provider);
            if ((!passwordLogin && !AuthConstants.PROVIDER_GOOGLE.equals(provider)
                    && !AuthConstants.PROVIDER_MICROSOFT.equals(provider))
                    || (passwordLogin && loginRequest.containsKey(AuthConstants.FIELD_TOKEN))
                    || (!passwordLogin && loginRequest.containsKey(AuthConstants.FIELD_PASSWORD))) {
                throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
            }
            String username = passwordLogin ? loginRequest.get(AuthConstants.FIELD_USERNAME) : null;
            String credential = loginRequest.get(passwordLogin ? AuthConstants.FIELD_PASSWORD : AuthConstants.FIELD_TOKEN);

            RegisteredClient client = clientAuthenticator.authenticateClient(request);
            ClientUserAuthenticationToken authToken = new ClientUserAuthenticationToken(username, credential, client.getClientId());
            authToken.setRegisteredClient(client);
            authToken.setDetails(provider);
            
            OAuth2AccessTokenResponse auth2AccessTokenResponse = authenticationFilterHelper.buildOAuth2AccessTokenResponse(authToken);

            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(auth2AccessTokenResponse, null, httpResponse);


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
