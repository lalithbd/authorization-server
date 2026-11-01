package com.mcueen.auth.service.oauth;

import com.mcueen.auth.model.user.AuthProvider;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MicrosoftOAuthProviderTest {
    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final MicrosoftOAuthProvider provider = new MicrosoftOAuthProvider(decoder);
    private final AuthProvider config = new AuthProvider();

    MicrosoftOAuthProviderTest() {
        config.setClientId("our-entra-client");
        config.setIssuer("https://login.microsoftonline.com/" + TENANT + "/v2.0");
    }

    @Test
    void validatesTenantAudienceAndSubjectWithoutAssumingEmailVerified() {
        when(decoder.decode("id-token")).thenReturn(jwt("our-entra-client", TENANT));

        OAuthUserInfo user = provider.validateToken("id-token", config);

        assertEquals("object-id", user.getProviderId());
        assertEquals("someone@example.com", user.getEmail());
        assertFalse(user.isEmailVerified());
    }

    @Test
    void rejectsWrongAudience() {
        when(decoder.decode("id-token")).thenReturn(jwt("another-client", TENANT));
        assertThrows(BadCredentialsException.class, () -> provider.validateToken("id-token", config));
    }

    @Test
    void rejectsWrongTenant() {
        when(decoder.decode("id-token")).thenReturn(jwt("our-entra-client", "22222222-2222-2222-2222-222222222222"));
        assertThrows(BadCredentialsException.class, () -> provider.validateToken("id-token", config));
    }

    @Test
    void rejectsUnconfiguredTenant() {
        config.setIssuer(null);
        when(decoder.decode("id-token")).thenReturn(jwt("our-entra-client", TENANT));
        assertThrows(BadCredentialsException.class, () -> provider.validateToken("id-token", config));
    }

    private Jwt jwt(String audience, String tenant) {
        return Jwt.withTokenValue("id-token")
                .header("alg", "RS256")
                .issuer("https://login.microsoftonline.com/" + tenant + "/v2.0")
                .audience(List.of(audience))
                .subject("subject")
                .issuedAt(Instant.now().minusSeconds(60))
                .expiresAt(Instant.now().plusSeconds(600))
                .claim("tid", tenant)
                .claim("oid", "object-id")
                .claim("email", "someone@example.com")
                .build();
    }
}
