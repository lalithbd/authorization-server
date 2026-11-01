package com.mcueen.auth.service.oauth;

import com.mcueen.auth.model.user.AuthProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class GoogleOAuthProviderTest {

    private static final String TOKEN_URL = "https://oauth2.googleapis.com/token";
    private static final String USER_INFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";
    private final RestTemplate restTemplate = new RestTemplate();
    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final MockRestServiceServer server = MockRestServiceServer.createServer(restTemplate);
    private final GoogleOAuthProvider provider = new GoogleOAuthProvider(restTemplate, decoder);
    private AuthProvider config;

    @BeforeEach
    void setUp() {
        config = new AuthProvider();
        config.setClientId("our-google-client");
        config.setClientSecret("secret");
        config.setTokenEndpointUrl(TOKEN_URL);
        config.setUserInfoUrl(USER_INFO_URL);
    }

    @Test
    void exchangesCodeAndMatchesVerifiedIdentityToUserInfo() {
        expectTokenResponse();
        when(decoder.decode("signed-id-token")).thenReturn(idToken("our-google-client",
                "https://accounts.google.com", "google-sub", true, Instant.now().plusSeconds(600)));
        server.expect(requestTo(USER_INFO_URL))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer google-access-token"))
                .andRespond(withSuccess("""
                        {"sub":"google-sub","email":"someone@example.com","email_verified":true,
                         "given_name":"Someone"}
                        """, MediaType.APPLICATION_JSON));

        OAuthUserInfo user = provider.exchangeCodeAndGetUserInfo("code", "https://app.example/callback", config);

        assertEquals("google-sub", user.getProviderId());
        assertEquals("someone@example.com", user.getEmail());
        assertEquals("Someone", user.getFirstName());
        assertEquals(true, user.isEmailVerified());
        server.verify();
    }

    @Test
    void rejectsIdTokenIssuedForAnotherClient() {
        expectRejectedIdToken(idToken("another-client", "https://accounts.google.com",
                "google-sub", true, Instant.now().plusSeconds(600)));
    }

    @Test
    void rejectsWrongIssuer() {
        expectRejectedIdToken(idToken("our-google-client", "https://untrusted.example",
                "google-sub", true, Instant.now().plusSeconds(600)));
    }

    @Test
    void rejectsExpiredIdToken() {
        expectRejectedIdToken(idToken("our-google-client", "https://accounts.google.com",
                "google-sub", true, Instant.now().minusSeconds(600)));
    }

    @Test
    void rejectsUnverifiedEmail() {
        expectRejectedIdToken(idToken("our-google-client", "https://accounts.google.com",
                "google-sub", false, Instant.now().plusSeconds(600)));
    }

    @Test
    void rejectsInvalidSignature() {
        expectTokenResponse();
        when(decoder.decode("signed-id-token")).thenThrow(new JwtException("Invalid signature"));

        assertThrows(BadCredentialsException.class,
                () -> provider.exchangeCodeAndGetUserInfo("code", "https://app.example/callback", config));
        server.verify();
    }

    @Test
    void rejectsAnotherAuthorizedParty() {
        Jwt token = Jwt.withTokenValue("signed-id-token")
                .header("alg", "RS256")
                .issuer("https://accounts.google.com")
                .subject("google-sub")
                .audience(List.of("our-google-client"))
                .issuedAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(600))
                .claim("email", "someone@example.com")
                .claim("email_verified", true)
                .claim("azp", "another-client")
                .build();
        expectRejectedIdToken(token);
    }

    @Test
    void rejectsMismatchedUserInfoSubject() {
        expectTokenResponse();
        when(decoder.decode("signed-id-token")).thenReturn(idToken("our-google-client",
                "https://accounts.google.com", "google-sub", true, Instant.now().plusSeconds(600)));
        server.expect(requestTo(USER_INFO_URL))
                .andRespond(withSuccess("""
                        {"sub":"another-sub","email":"someone@example.com","email_verified":true}
                        """, MediaType.APPLICATION_JSON));

        assertThrows(BadCredentialsException.class,
                () -> provider.exchangeCodeAndGetUserInfo("code", "https://app.example/callback", config));
        server.verify();
    }

    @Test
    void rejectsTokenResponseWithoutIdToken() {
        server.expect(requestTo(TOKEN_URL))
                .andRespond(withSuccess("{\"access_token\":\"google-access-token\"}", MediaType.APPLICATION_JSON));

        assertThrows(BadCredentialsException.class,
                () -> provider.exchangeCodeAndGetUserInfo("code", "https://app.example/callback", config));
        server.verify();
    }

    @Test
    void rejectsMismatchedUserInfoEmail() {
        expectTokenResponse();
        when(decoder.decode("signed-id-token")).thenReturn(idToken("our-google-client",
                "https://accounts.google.com", "google-sub", true, Instant.now().plusSeconds(600)));
        server.expect(requestTo(USER_INFO_URL))
                .andRespond(withSuccess("""
                        {"sub":"google-sub","email":"other@example.com","email_verified":true}
                        """, MediaType.APPLICATION_JSON));

        assertThrows(BadCredentialsException.class,
                () -> provider.exchangeCodeAndGetUserInfo("code", "https://app.example/callback", config));
        server.verify();
    }

    @Test
    void validatesDirectIdTokenForConfiguredGoogleClient() {
        when(decoder.decode("signed-id-token")).thenReturn(idToken("our-google-client",
                "https://accounts.google.com", "google-sub", true, Instant.now().plusSeconds(600)));

        OAuthUserInfo user = provider.validateToken("signed-id-token", config);

        assertEquals("google-sub", user.getProviderId());
        assertEquals("someone@example.com", user.getEmail());
        assertEquals(true, user.isEmailVerified());
        server.verify();
    }

    @Test
    void rejectsDirectIdTokenFromAnotherClient() {
        when(decoder.decode("signed-id-token")).thenReturn(idToken("other-client",
                "https://accounts.google.com", "google-sub", true, Instant.now().plusSeconds(600)));

        assertThrows(BadCredentialsException.class, () -> provider.validateToken("signed-id-token", config));
        server.verify();
    }

    private void expectRejectedIdToken(Jwt token) {
        expectTokenResponse();
        when(decoder.decode("signed-id-token")).thenReturn(token);

        assertThrows(BadCredentialsException.class,
                () -> provider.exchangeCodeAndGetUserInfo("code", "https://app.example/callback", config));
        server.verify();
    }

    private void expectTokenResponse() {
        server.expect(requestTo(TOKEN_URL))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess("""
                        {"id_token":"signed-id-token","access_token":"google-access-token"}
                        """, MediaType.APPLICATION_JSON));
    }

    private Jwt idToken(String audience, String issuer, String subject, boolean verified, Instant expiresAt) {
        return Jwt.withTokenValue("signed-id-token")
                .header("alg", "RS256")
                .issuer(issuer)
                .subject(subject)
                .audience(List.of(audience))
                .issuedAt(expiresAt.minusSeconds(60))
                .expiresAt(expiresAt)
                .claim("email", "someone@example.com")
                .claim("email_verified", verified)
                .build();
    }
}
