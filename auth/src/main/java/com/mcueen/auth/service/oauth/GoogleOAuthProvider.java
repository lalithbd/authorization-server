package com.mcueen.auth.service.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.model.user.AuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Set;

@Service
public class GoogleOAuthProvider implements OAuthProvider {

    private static final Set<String> ISSUERS = Set.of("accounts.google.com", "https://accounts.google.com");
    private static final String JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private com.mcueen.auth.service.oauth.IdTokenVerifier idTokenVerifier;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Verifies the ID token's signature, expiry, issuer and audience locally against Google's
     * JWKS. The previous call to the {@code tokeninfo} endpoint only reported whether the token
     * was well-formed, so a token issued to any other Google application was accepted here.
     */
    @Override
    public OAuthUserInfo validateToken(String idToken, AuthProvider authProvider) {
        Jwt jwt = idTokenVerifier.verify(idToken, authProvider, ISSUERS, JWKS_URI);
        return mapUserInfo(jwt);
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

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            String tokenResponse = restTemplate.postForObject(
                    authProvider.getTokenEndpointUrl(), request, String.class);
            JsonNode tokenJson = objectMapper.readTree(tokenResponse);

            if (tokenJson.has("error")) {
                throw new RuntimeException("Token exchange failed: " + tokenJson.get("error").asText());
            }

            // The code was redeemed over a back channel using our client secret, so the id_token
            // in the response is bound to this application. Verify it anyway and read the identity
            // from its claims: the userinfo endpoint reports whoever owns the access token, which
            // is a weaker statement than what the id_token asserts.
            JsonNode idTokenNode = tokenJson.get("id_token");
            if (idTokenNode != null && !idTokenNode.isNull()) {
                Jwt jwt = idTokenVerifier.verify(idTokenNode.asText(), authProvider, ISSUERS, JWKS_URI);
                return mapUserInfo(jwt);
            }

            // Providers configured for plain OAuth2 return no id_token; fall back to userinfo.
            String accessToken = tokenJson.get("access_token").asText();
            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userInfoRequest = new HttpEntity<>(userInfoHeaders);

            String userInfoResponse = restTemplate.exchange(
                    authProvider.getUserInfoUrl(), HttpMethod.GET, userInfoRequest, String.class).getBody();
            JsonNode userInfoJson = objectMapper.readTree(userInfoResponse);

            return mapUserInfo(userInfoJson);
        } catch (Exception e) {
            throw new RuntimeException("Failed to exchange Google code: " + e.getMessage());
        }
    }

    private OAuthUserInfo mapUserInfo(Jwt jwt) {
        OAuthUserInfo userInfo = new OAuthUserInfo();
        userInfo.setProviderId(jwt.getSubject());
        userInfo.setEmail(jwt.getClaimAsString("email"));
        // Google has historically emitted this claim as both a JSON boolean and the string
        // "true", so accept either rather than silently reading one form as unverified.
        Object emailVerified = jwt.getClaim("email_verified");
        userInfo.setEmailVerified(Boolean.TRUE.equals(emailVerified)
                || (emailVerified instanceof String s && Boolean.parseBoolean(s)));
        userInfo.setName(jwt.getClaimAsString("name"));
        userInfo.setFirstName(jwt.getClaimAsString("given_name"));
        userInfo.setLastName(jwt.getClaimAsString("family_name"));
        return userInfo;
    }

    private OAuthUserInfo mapUserInfo(JsonNode jsonNode) {
        OAuthUserInfo userInfo = new OAuthUserInfo();
        userInfo.setProviderId(jsonNode.get("sub").asText());
        userInfo.setEmail(jsonNode.get("email").asText());
        // Absent claim means unproven, not verified.
        userInfo.setEmailVerified(jsonNode.path("email_verified").asBoolean(false));
        userInfo.setName(jsonNode.has("name") ? jsonNode.get("name").asText() : null);
        userInfo.setFirstName(jsonNode.has("given_name") ? jsonNode.get("given_name").asText() : null);
        userInfo.setLastName(jsonNode.has("family_name") ? jsonNode.get("family_name").asText() : null);
        return userInfo;
    }

    @Override
    public String getProviderName() {
        return "google";
    }
}
