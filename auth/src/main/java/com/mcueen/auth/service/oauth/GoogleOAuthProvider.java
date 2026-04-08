package com.mcueen.auth.service.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcueen.auth.model.user.AuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Service
public class GoogleOAuthProvider implements OAuthProvider {

    @Autowired
    private RestTemplate restTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public OAuthUserInfo validateToken(String idToken) {
        try {
            String url = "https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken;
            String response = restTemplate.getForObject(url, String.class);
            JsonNode jsonNode = objectMapper.readTree(response);

            if (jsonNode.has("error")) {
                throw new RuntimeException("Invalid Google ID token");
            }

            return mapUserInfo(jsonNode);
        } catch (Exception e) {
            throw new RuntimeException("Failed to validate Google token: " + e.getMessage());
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

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            String tokenResponse = restTemplate.postForObject(
                    authProvider.getTokenEndpointUrl(), request, String.class);
            JsonNode tokenJson = objectMapper.readTree(tokenResponse);

            if (tokenJson.has("error")) {
                throw new RuntimeException("Token exchange failed: " + tokenJson.get("error").asText());
            }

            // Use access_token to get user info from userinfo endpoint
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

    private OAuthUserInfo mapUserInfo(JsonNode jsonNode) {
        OAuthUserInfo userInfo = new OAuthUserInfo();
        userInfo.setProviderId(jsonNode.get("sub").asText());
        userInfo.setEmail(jsonNode.get("email").asText());
        userInfo.setEmailVerified(jsonNode.get("email_verified").asBoolean());
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
