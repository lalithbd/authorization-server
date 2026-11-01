package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.AuthProviderRepository;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.oauth.OAuthProviderFactory;
import com.mcueen.auth.service.oauth.OAuthProvider;
import com.mcueen.auth.service.oauth.OAuthUserInfo;
import com.mcueen.auth.util.auth.AuthGrantTypes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FederatedAuthenticationProviderTest {

    private final UserRepository users = mock(UserRepository.class);
    private final AuthProviderRepository configs = mock(AuthProviderRepository.class);
    private final OAuthProviderFactory providerFactory = mock(OAuthProviderFactory.class);
    private final AuthenticationProviderHelper helper = mock(AuthenticationProviderHelper.class);
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    private final FederatedAuthenticationProvider provider =
            new FederatedAuthenticationProvider(users, configs, encoder, providerFactory, helper);
    private final RegisteredClient client = mock(RegisteredClient.class);

    @BeforeEach
    void setUp() {
        User user = new User();
        user.setEmail("user@example.com");
        user.setPassword(encoder.encode("correct-password"));
        when(users.findByEmail("user@example.com")).thenReturn(Optional.of(user));
    }

    @Test
    void verifiesDatabasePasswordBeforeIssuingForResolvedUser() {
        OAuth2Authorization authorization = stubAuthorization();
        when(helper.getOAuth2Authorization(any(), any(), any())).thenAnswer(invocation -> {
            Authentication principal = invocation.getArgument(0);
            assertEquals("user@example.com", principal.getName());
            assertNull(principal.getCredentials());
            assertEquals(client, invocation.getArgument(1));
            assertEquals(AuthGrantTypes.PASSWORD, invocation.getArgument(2));
            return authorization;
        });

        Authentication result = provider.authenticate(login("email", "correct-password"));

        assertEquals("user@example.com", result.getName());
        verify(helper).getOAuth2Authorization(any(), any(), any());
    }

    private OAuth2Authorization stubAuthorization() {
        OAuth2Authorization authorization = mock(OAuth2Authorization.class);
        @SuppressWarnings("unchecked")
        OAuth2Authorization.Token<OAuth2AccessToken> access = mock(OAuth2Authorization.Token.class);
        @SuppressWarnings("unchecked")
        OAuth2Authorization.Token<OAuth2RefreshToken> refresh = mock(OAuth2Authorization.Token.class);
        when(access.getToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                "access", Instant.now(), Instant.now().plusSeconds(60)));
        when(refresh.getToken()).thenReturn(new OAuth2RefreshToken("refresh", Instant.now()));
        when(authorization.getAccessToken()).thenReturn(access);
        when(authorization.getRefreshToken()).thenReturn(refresh);
        return authorization;
    }

    @Test
    void issuesSocialLoginForVerifiedProviderIdentityNotRequestUsername() {
        OAuthUserInfo identity = new OAuthUserInfo();
        identity.setProviderId("google-sub");
        identity.setEmail("user@example.com");
        identity.setEmailVerified(true);
        AuthProvider config = configuredProvider("google");
        OAuthProvider google = mock(OAuthProvider.class);
        when(providerFactory.getProvider("google")).thenReturn(google);
        when(google.validateToken("provider-token", config)).thenReturn(identity);
        User linkedUser = users.findByEmail("user@example.com").orElseThrow();
        when(users.findByOauthProviderAndOauthProviderId("google", "google-sub"))
                .thenReturn(Optional.of(linkedUser));
        OAuth2Authorization authorization = stubAuthorization();
        when(helper.getOAuth2Authorization(any(), any(), any())).thenAnswer(invocation -> {
            assertEquals("user@example.com", ((Authentication) invocation.getArgument(0)).getName());
            assertNull(((Authentication) invocation.getArgument(0)).getCredentials());
            assertEquals(AuthGrantTypes.TOKEN_EXCHANGE, invocation.getArgument(2));
            return authorization;
        });

        ClientUserAuthenticationToken request = new ClientUserAuthenticationToken("other@example.com", "provider-token", "client");
        request.setRegisteredClient(client);
        request.setDetails("google");
        Authentication result = provider.authenticate(request);

        assertEquals("user@example.com", result.getName());
        verify(users, never()).findByEmail("other@example.com");
    }

    @Test
    void rejectsUnverifiedMicrosoftIdentityWithoutExistingLink() {
        OAuthUserInfo identity = new OAuthUserInfo();
        identity.setProviderId("object-id");
        identity.setEmail("someone@example.com");
        AuthProvider config = configuredProvider("microsoft");
        OAuthProvider microsoft = mock(OAuthProvider.class);
        when(providerFactory.getProvider("microsoft")).thenReturn(microsoft);
        when(microsoft.validateToken("provider-token", config)).thenReturn(identity);
        when(users.findByOauthProviderAndOauthProviderId("microsoft", "object-id")).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(login("microsoft", "provider-token")));
        verifyNoInteractions(helper);
        verify(users, never()).save(any());
    }

    @Test
    void permitsExistingMicrosoftLinkWithoutTrustingEmailClaim() {
        OAuthUserInfo identity = new OAuthUserInfo();
        identity.setProviderId("object-id");
        identity.setEmail("changed@example.com");
        AuthProvider config = configuredProvider("microsoft");
        OAuthProvider microsoft = mock(OAuthProvider.class);
        when(providerFactory.getProvider("microsoft")).thenReturn(microsoft);
        when(microsoft.validateToken("provider-token", config)).thenReturn(identity);
        User linked = users.findByEmail("user@example.com").orElseThrow();
        when(users.findByOauthProviderAndOauthProviderId("microsoft", "object-id")).thenReturn(Optional.of(linked));
        OAuth2Authorization authorization = stubAuthorization();
        when(helper.getOAuth2Authorization(any(), any(), any())).thenAnswer(invocation -> {
            assertEquals("user@example.com", ((Authentication) invocation.getArgument(0)).getName());
            return authorization;
        });

        Authentication result = provider.authenticate(login("microsoft", "provider-token"));

        assertEquals("user@example.com", result.getName());
        verify(users, never()).findByEmail("changed@example.com");
    }

    @Test
    void createsGoogleAccountOnlyForUnusedVerifiedEmail() {
        OAuthUserInfo identity = new OAuthUserInfo();
        identity.setProviderId("new-google-sub");
        identity.setEmail("new@example.com");
        identity.setEmailVerified(true);
        AuthProvider config = configuredProvider("google");
        OAuthProvider google = mock(OAuthProvider.class);
        when(providerFactory.getProvider("google")).thenReturn(google);
        when(google.validateToken("provider-token", config)).thenReturn(identity);
        when(users.findByOauthProviderAndOauthProviderId("google", "new-google-sub")).thenReturn(Optional.empty());
        when(users.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(users.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        OAuth2Authorization authorization = stubAuthorization();
        when(helper.getOAuth2Authorization(any(), any(), any())).thenReturn(authorization);

        Authentication result = provider.authenticate(login("google", "provider-token"));

        assertEquals("new@example.com", result.getName());
        verify(users).save(org.mockito.ArgumentMatchers.argThat(user ->
                "google".equals(user.getOauthProvider()) && "new-google-sub".equals(user.getOauthProviderId())));
    }

    @Test
    void rejectsAutomaticEmailLinkingToPasswordAccount() {
        OAuthUserInfo identity = new OAuthUserInfo();
        identity.setProviderId("new-google-sub");
        identity.setEmail("user@example.com");
        identity.setEmailVerified(true);
        AuthProvider config = configuredProvider("google");
        OAuthProvider google = mock(OAuthProvider.class);
        when(providerFactory.getProvider("google")).thenReturn(google);
        when(google.validateToken("provider-token", config)).thenReturn(identity);
        when(users.findByOauthProviderAndOauthProviderId("google", "new-google-sub")).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(login("google", "provider-token")));
        verifyNoInteractions(helper);
        verify(users, never()).save(any());
    }

    @Test
    void rejectsDisabledProvider() {
        AuthProvider config = configuredProvider("microsoft");
        config.setEnabled(false);

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(login("microsoft", "provider-token")));
        verifyNoInteractions(providerFactory, helper);
    }

    @Test
    void rejectsWrongPassword() {
        assertThrows(BadCredentialsException.class, () -> provider.authenticate(login("email", "wrong-password")));
        verifyNoInteractions(helper);
    }

    @Test
    void rejectsMissingPassword() {
        assertThrows(BadCredentialsException.class, () -> provider.authenticate(login("email", null)));
        verifyNoInteractions(users, helper);
    }

    @Test
    void rejectsPasswordLoginForOauthOnlyAccount() {
        User user = new User();
        user.setEmail("user@example.com");
        when(users.findByEmail(user.getEmail())).thenReturn(Optional.of(user));

        assertThrows(BadCredentialsException.class, () -> provider.authenticate(login("email", "correct-password")));
        verifyNoInteractions(helper);
    }

    private ClientUserAuthenticationToken login(String authProvider, String password) {
        ClientUserAuthenticationToken token = new ClientUserAuthenticationToken("user@example.com", password, "client");
        token.setDetails(authProvider);
        token.setRegisteredClient(client);
        return token;
    }

    private AuthProvider configuredProvider(String providerName) {
        AuthProvider config = new AuthProvider();
        config.setName(providerName);
        config.setClientId("provider-client");
        when(configs.findByName(providerName)).thenReturn(Optional.of(config));
        return config;
    }
}
