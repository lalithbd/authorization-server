package com.mcueen.auth.service.oauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class MicrosoftOAuthProvider implements OAuthProvider {

    @Autowired
    private RestTemplate restTemplate;
    
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public OAuthUserInfo validateToken(String accessToken) {
        try {
            String url = "https://graph.microsoft.com/v1.0/me";
            String response = restTemplate.getForObject(
                url + "?access_token=" + accessToken, 
                String.class
            );
            JsonNode jsonNode = objectMapper.readTree(response);
            
            if (jsonNode.has("error")) {
                throw new RuntimeException("Invalid Microsoft token");
            }
            
            OAuthUserInfo userInfo = new OAuthUserInfo();
            userInfo.setProviderId(jsonNode.get("id").asText());
            userInfo.setEmail(jsonNode.has("mail") ? jsonNode.get("mail").asText() : 
                             jsonNode.has("userPrincipalName") ? jsonNode.get("userPrincipalName").asText() : null);
            userInfo.setEmailVerified(true); // Microsoft emails are verified
            userInfo.setFirstName(jsonNode.has("givenName") ? jsonNode.get("givenName").asText() : null);
            userInfo.setLastName(jsonNode.has("surname") ? jsonNode.get("surname").asText() : null);
            userInfo.setName(jsonNode.has("displayName") ? jsonNode.get("displayName").asText() : null);
            
            return userInfo;
        } catch (Exception e) {
            throw new RuntimeException("Failed to validate Microsoft token: " + e.getMessage());
        }
    }

    @Override
    public String getProviderName() {
        return "microsoft";
    }
}
