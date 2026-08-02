package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.UnAuthorizedResponse;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthEndpoints;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
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

@Component
public class UsernamePasswordAuthHandler extends OncePerRequestFilter {

    @Autowired
    private AuthenticationFilterHelper authenticationFilterHelper;

    @Autowired
    private ObjectMapper objectMapper;

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        if (!AuthEndpoints.LOGIN.equals(request.getServletPath()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Map<String, String> loginRequest = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {
            });
            String provider = loginRequest.getOrDefault(AuthConstants.FIELD_PROVIDER, AuthConstants.PROVIDER_EMAIL);
            String username = loginRequest.get(AuthConstants.FIELD_USERNAME);
            String credential = provider.equalsIgnoreCase(AuthConstants.PROVIDER_EMAIL) ? loginRequest.get(AuthConstants.FIELD_PASSWORD) : loginRequest.get(AuthConstants.FIELD_TOKEN);
                
            String authHeader = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);
            if(authHeader == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS_JSON);
                return;
            }
            String base64Credentials = authHeader.substring(AuthConstants.BASIC_PREFIX_LENGTH);
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
            String[] parts = credentials.split(":", 2);
            
            ClientUserAuthenticationToken authToken = new ClientUserAuthenticationToken(username, credential, parts[0], parts[1]);
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
