package com.mcueen.auth.service.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.model.user.AuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.regex.Pattern;

@Service
public class MicrosoftOAuthProvider implements OAuthProvider {

    private static final Pattern TENANT_ID = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    private final JwtDecoder idTokenDecoder;

    @Autowired
    private RestTemplate restTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public MicrosoftOAuthProvider() {
        this(NimbusJwtDecoder.withJwkSetUri("https://login.microsoftonline.com/common/discovery/v2.0/keys").build());
    }

    MicrosoftOAuthProvider(JwtDecoder idTokenDecoder) {
        this.idTokenDecoder = idTokenDecoder;
    }

    @Override
    public OAuthUserInfo validateToken(String idToken, AuthProvider authProvider) {
        try {
            if (idToken == null || idToken.isBlank()) {
                throw new BadCredentialsException("Invalid Microsoft ID token");
            }
            Jwt verified = idTokenDecoder.decode(idToken);
            String tenantId = verified.getClaimAsString("tid");
            String objectId = verified.getClaimAsString("oid");
            String email = verified.getClaimAsString("email");
            if (email == null || email.isBlank()) {
                email = verified.getClaimAsString("preferred_username");
            }
            String issuer = tenantId == null ? null : "https://login.microsoftonline.com/" + tenantId + "/v2.0";
            if (tenantId == null || !TENANT_ID.matcher(tenantId).matches()
                    || authProvider.getIssuer() == null || !authProvider.getIssuer().equals(issuer)
                    || authProvider.getClientId() == null || authProvider.getClientId().isBlank()
                    || !verified.getAudience().contains(authProvider.getClientId())
                    || verified.getExpiresAt() == null || !verified.getExpiresAt().isAfter(Instant.now())
                    || objectId == null || objectId.isBlank()) {
                throw new BadCredentialsException("Invalid Microsoft identity");
            }
            OAuthUserInfo userInfo = new OAuthUserInfo();
            userInfo.setProviderId(objectId);
            userInfo.setEmail(email);
            // A Graph mail/UPN (and an ID token email) is not proof of mailbox ownership.
            userInfo.setEmailVerified(Boolean.TRUE.equals(verified.getClaimAsBoolean("email_verified")));
            userInfo.setFirstName(verified.getClaimAsString("given_name"));
            userInfo.setLastName(verified.getClaimAsString("family_name"));
            userInfo.setName(verified.getClaimAsString("name"));
            return userInfo;
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid Microsoft ID token", e);
        }
    }

    @Override
    public OAuthUserInfo exchangeCodeAndGetUserInfo(String code, String redirectUri, AuthProvider authProvider) {
        try {
            // Exchange code for tokens
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("code", code);
            params.add("client_id", authProvider.getClientId());
            params.add("client_secret", authProvider.getClientSecret());
            params.add("redirect_uri", redirectUri);
            params.add("grant_type", "authorization_code");
            params.add("scope", authProvider.getScope());

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            String tokenResponse = restTemplate.postForObject(
                    authProvider.getTokenEndpointUrl(), request, String.class);
            JsonNode tokenJson = objectMapper.readTree(tokenResponse);

            if (tokenJson.has("error")) {
                throw new RuntimeException("Token exchange failed: " + tokenJson.get("error_description").asText());
            }

            // Use access_token to call Graph API for user info
            String accessToken = tokenJson.get("access_token").asText();
            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userInfoRequest = new HttpEntity<>(userInfoHeaders);

            String userInfoResponse = restTemplate.exchange(
                    authProvider.getUserInfoUrl(), HttpMethod.GET, userInfoRequest, String.class).getBody();
            JsonNode userInfoJson = objectMapper.readTree(userInfoResponse);

            return mapUserInfo(userInfoJson);
        } catch (Exception e) {
            throw new RuntimeException("Failed to exchange Microsoft code: " + e.getMessage());
        }
    }

    private OAuthUserInfo mapUserInfo(JsonNode jsonNode) {
        OAuthUserInfo userInfo = new OAuthUserInfo();
        userInfo.setProviderId(jsonNode.get("id").asText());
        userInfo.setEmail(jsonNode.has("mail") ? jsonNode.get("mail").asText() :
                jsonNode.has("userPrincipalName") ? jsonNode.get("userPrincipalName").asText() : null);
        userInfo.setEmailVerified(true);
        userInfo.setFirstName(jsonNode.has("givenName") ? jsonNode.get("givenName").asText() : null);
        userInfo.setLastName(jsonNode.has("surname") ? jsonNode.get("surname").asText() : null);
        userInfo.setName(jsonNode.has("displayName") ? jsonNode.get("displayName").asText() : null);
        return userInfo;
    }

    @Override
    public String getProviderName() {
        return "microsoft";
    }
}
