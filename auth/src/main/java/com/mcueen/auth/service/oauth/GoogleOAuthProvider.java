package com.mcueen.auth.service.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
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
            
            OAuthUserInfo userInfo = new OAuthUserInfo();
            userInfo.setProviderId(jsonNode.get("sub").asText());
            userInfo.setEmail(jsonNode.get("email").asText());
            userInfo.setEmailVerified(jsonNode.get("email_verified").asBoolean());
            userInfo.setName(jsonNode.has("name") ? jsonNode.get("name").asText() : null);
            userInfo.setFirstName(jsonNode.has("given_name") ? jsonNode.get("given_name").asText() : null);
            userInfo.setLastName(jsonNode.has("family_name") ? jsonNode.get("family_name").asText() : null);
            
            return userInfo;
        } catch (Exception e) {
            throw new RuntimeException("Failed to validate Google token: " + e.getMessage());
        }
    }

    @Override
    public String getProviderName() {
        return "google";
    }
}
