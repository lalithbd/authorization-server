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
public class MicrosoftOAuthProvider implements OAuthProvider {

    /**
     * {@code {tenantid}} is substituted with the token's own {@code tid} claim during validation,
     * which is how Microsoft documents the issuer for multi-tenant applications.
     */
    private static final Set<String> ISSUERS = Set.of("https://login.microsoftonline.com/{tenantid}/v2.0");
    private static final String JWKS_URI = "https://login.microsoftonline.com/common/discovery/v2.0/keys";

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private IdTokenVerifier idTokenVerifier;

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Expects an ID token, not a Graph access token.
     * <p>
     * The previous implementation called Graph {@code /me} with whatever token it was handed and
     * trusted the answer. A Graph access token has Graph as its audience, so nothing in it binds
     * it to this application — any token from any Microsoft app with Graph access would have
     * authenticated its bearer here. An ID token carries our client id in {@code aud}, which is
     * what makes verification possible.
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

            // Prefer the id_token: it is signed, audience-bound, and states the email's
            // verification status. Graph reports an address without saying whether it was proven.
            JsonNode idTokenNode = tokenJson.get("id_token");
            if (idTokenNode != null && !idTokenNode.isNull()) {
                Jwt jwt = idTokenVerifier.verify(idTokenNode.asText(), authProvider, ISSUERS, JWKS_URI);
                return mapUserInfo(jwt);
            }

            // Bearer header, not a query parameter: URLs reach access logs, proxies and Referer.
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

    private OAuthUserInfo mapUserInfo(Jwt jwt) {
        OAuthUserInfo userInfo = new OAuthUserInfo();
        userInfo.setProviderId(jwt.getSubject());

        String email = jwt.getClaimAsString("email");
        if (email == null) {
            email = jwt.getClaimAsString("preferred_username");
        }
        userInfo.setEmail(email);

        // Entra ID has no email_verified claim. The nearest equivalent is xms_edov ("email domain
        // owner verified"), an optional claim the app registration must request. Without it there
        // is no evidence the address was proven, and a personal account can set an arbitrary one —
        // so treat it as unverified rather than assuming, as this previously did.
        userInfo.setEmailVerified(Boolean.TRUE.equals(jwt.getClaim("xms_edov")));

        userInfo.setName(jwt.getClaimAsString("name"));
        userInfo.setFirstName(jwt.getClaimAsString("given_name"));
        userInfo.setLastName(jwt.getClaimAsString("family_name"));
        return userInfo;
    }

    private OAuthUserInfo mapUserInfo(JsonNode jsonNode) {
        OAuthUserInfo userInfo = new OAuthUserInfo();
        userInfo.setProviderId(jsonNode.get("id").asText());
        userInfo.setEmail(jsonNode.has("mail") && !jsonNode.get("mail").isNull()
                ? jsonNode.get("mail").asText()
                : jsonNode.has("userPrincipalName") ? jsonNode.get("userPrincipalName").asText() : null);
        // Graph states no verification status, so this path cannot assert one.
        userInfo.setEmailVerified(false);
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
