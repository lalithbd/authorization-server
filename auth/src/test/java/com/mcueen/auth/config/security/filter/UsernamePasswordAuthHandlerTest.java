package com.mcueen.auth.config.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.config.security.model.ClientAuthenticator;
import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.util.auth.AuthEndpoints;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class UsernamePasswordAuthHandlerTest {

    private final AuthenticationFilterHelper helper = mock(AuthenticationFilterHelper.class);
    private final ClientAuthenticator clientAuthenticator = mock(ClientAuthenticator.class);
    private final UsernamePasswordAuthHandler handler =
            new UsernamePasswordAuthHandler(helper, new ObjectMapper(), clientAuthenticator);

    @Test
    void passesProviderTokenWithoutTrustingRequestUsername() throws Exception {
        MockHttpServletRequest request = request("""
                {"provider":"google","username":"other@example.com","token":"provider-token"}
                """);
        MockHttpServletResponse response = new MockHttpServletResponse();
        RegisteredClient client = mock(RegisteredClient.class);
        when(client.getClientId()).thenReturn("server-client");
        when(clientAuthenticator.authenticateClient(request)).thenReturn(client);
        when(helper.buildOAuth2AccessTokenResponse(any())).thenAnswer(invocation -> {
            ClientUserAuthenticationToken token = invocation.getArgument(0);
            assertEquals(null, token.getPrincipal());
            assertEquals("provider-token", token.getCredentials());
            assertEquals("google", token.getDetails());
            return OAuth2AccessTokenResponse.withToken("access")
                    .tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(60).build();
        });

        handler.doFilter(request, response, mock(jakarta.servlet.FilterChain.class));

        assertEquals(200, response.getStatus());
    }

    @Test
    void rejectsTokenFieldEvenWithPassword() throws Exception {
        assertUnauthorized("""
                {"provider":"email","username":"user@example.com","password":"password","token":"provider-token"}
                """);
    }

    @Test
    void acceptsLegacyPasswordRequestWithoutProvider() throws Exception {
        MockHttpServletRequest request = request("""
                {"username":"user@example.com","password":"correct-password"}
                """);
        MockHttpServletResponse response = new MockHttpServletResponse();
        RegisteredClient client = mock(RegisteredClient.class);
        when(client.getClientId()).thenReturn("legacy-client");
        when(clientAuthenticator.authenticateClient(request)).thenReturn(client);
        when(helper.buildOAuth2AccessTokenResponse(any())).thenAnswer(invocation -> {
            ClientUserAuthenticationToken token = invocation.getArgument(0);
            assertEquals("user@example.com", token.getName());
            assertEquals("correct-password", token.getCredentials());
            assertEquals("email", token.getDetails());
            assertEquals(client, token.getRegisteredClient());
            return OAuth2AccessTokenResponse.withToken("access")
                    .tokenType(OAuth2AccessToken.TokenType.BEARER).expiresIn(60).build();
        });

        handler.doFilter(request, response, mock(jakarta.servlet.FilterChain.class));

        assertEquals(200, response.getStatus());
    }

    private void assertUnauthorized(String body) throws Exception {
        MockHttpServletRequest request = request(body);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.doFilter(request, response, mock(jakarta.servlet.FilterChain.class));

        assertEquals(401, response.getStatus());
        verifyNoInteractions(helper, clientAuthenticator);
    }

    private MockHttpServletRequest request(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", AuthEndpoints.LOGIN);
        request.setServletPath(AuthEndpoints.LOGIN);
        request.setContentType("application/json");
        request.setContent(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return request;
    }
}
