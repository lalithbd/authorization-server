package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

public class UsernamePasswordAuthFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final ObjectMapper objectMapper;
    private final OAuth2TokenGenerator<?> tokenGenerator;
    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

    public UsernamePasswordAuthFilter(AuthenticationManager authenticationManager, OAuth2TokenGenerator<?> tokenGenerator) {
        this.authenticationManager = authenticationManager;
        this.objectMapper = new ObjectMapper();
        this.tokenGenerator = tokenGenerator;
    }

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // Only intercept login requests
        if (!"/auth/login".equals(request.getServletPath()) || !"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            // Parse JSON request body
            Map<String, String> loginRequest = objectMapper.readValue(request.getInputStream(), new TypeReference<>() {
            });
            String username = loginRequest.get("username");
            String password = loginRequest.get("password");
            String authHeader = request.getHeader("Authorization");
            if(authHeader == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Invalid Client credentials\"}");
                return;
            }
            String base64Credentials = authHeader.substring(6);

            // Decode Base64 to get client_id:client_secret
            String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);

            // Split into client_id and client_secret
            String[] parts = credentials.split(":", 2);
            // Create authentication token
            ClientUserAuthenticationToken authentication = (ClientUserAuthenticationToken) authenticationManager.authenticate(
                    new ClientUserAuthenticationToken(username, password, parts[0], parts[1]));

            // Set authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)  // Requesting an access token
                    .principal(authentication)  // Authenticated user
                    .registeredClient(authentication.getRegisteredClient())  // OAuth2 client details
                    .authorizedScopes(Set.of("read", "write"))  // Define scopes
//                    .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                    .build();
            OAuth2Token oAuth2Token = tokenGenerator.generate(tokenContext);
            OAuth2AccessTokenResponse.Builder builder = OAuth2AccessTokenResponse
                    .withToken(oAuth2Token.getTokenValue())
                    .tokenType(OAuth2AccessToken.TokenType.BEARER)
                    .scopes(tokenContext.getAuthorizedScopes())
                    .expiresIn(ChronoUnit.SECONDS.between(oAuth2Token.getIssuedAt(), oAuth2Token.getExpiresAt()));


//            OAuth2Authorization authorization = authorizationBuilder.build();
//
//            this.authorizationService.save(authorization);
//
            ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
            this.accessTokenResponseConverter.write(builder.build(), null, httpResponse);


        } catch (AuthenticationException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"Invalid username or password\"}");
        }
    }
}
