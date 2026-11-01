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

@Service
public class GoogleOAuthProvider implements OAuthProvider {

    private final RestTemplate restTemplate;
    private final JwtDecoder idTokenDecoder;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public GoogleOAuthProvider(RestTemplate restTemplate) {
        this(restTemplate, NimbusJwtDecoder.withJwkSetUri("https://www.googleapis.com/oauth2/v3/certs").build());
    }

    GoogleOAuthProvider(RestTemplate restTemplate, JwtDecoder idTokenDecoder) {
        this.restTemplate = restTemplate;
        this.idTokenDecoder = idTokenDecoder;
    }

    @Override
    public OAuthUserInfo validateToken(String idToken, AuthProvider authProvider) {
        try {
            Jwt verified = verifyIdToken(idToken, authProvider);
            OAuthUserInfo userInfo = new OAuthUserInfo();
            userInfo.setProviderId(verified.getSubject());
            userInfo.setEmail(verified.getClaimAsString("email"));
            userInfo.setEmailVerified(true);
            userInfo.setName(verified.getClaimAsString("name"));
            userInfo.setFirstName(verified.getClaimAsString("given_name"));
            userInfo.setLastName(verified.getClaimAsString("family_name"));
            return userInfo;
        } catch (Exception e) {
            throw new BadCredentialsException("Invalid Google ID token", e);
        }
    }

    @Override
    public OAuthUserInfo exchangeCodeAndGetUserInfo(String code, String redirectUri, AuthProvider authProvider) {
        try {
            MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
            params.add("code", code);
            params.add("client_id", authProvider.getClientId());
            params.add("client_secret", authProvider.getClientSecret());
            params.add("redirect_uri", redirectUri);
            params.add("grant_type", "authorization_code");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

            String tokenResponse = restTemplate.postForObject(authProvider.getTokenEndpointUrl(), request, String.class);
            JsonNode tokenJson = objectMapper.readTree(tokenResponse);

            if (tokenJson == null || tokenJson.has("error")
                    || tokenJson.path("id_token").asText().isBlank()
                    || tokenJson.path("access_token").asText().isBlank()) {
                throw new BadCredentialsException("Invalid Google token response");
            }

            Jwt idToken = verifyIdToken(tokenJson.get("id_token").asText(), authProvider);
            String subject = idToken.getSubject();
            String email = idToken.getClaimAsString("email");

            String accessToken = tokenJson.get("access_token").asText();
            HttpHeaders userInfoHeaders = new HttpHeaders();
            userInfoHeaders.setBearerAuth(accessToken);
            HttpEntity<Void> userInfoRequest = new HttpEntity<>(userInfoHeaders);

            String userInfoResponse = restTemplate.exchange(authProvider.getUserInfoUrl(), HttpMethod.GET, userInfoRequest, String.class).getBody();
            JsonNode userInfoJson = objectMapper.readTree(userInfoResponse);

            if (userInfoJson == null || !subject.equals(userInfoJson.path("sub").asText())
                    || !email.equals(userInfoJson.path("email").asText())
                    || !userInfoJson.path("email_verified").asBoolean(false)) {
                throw new BadCredentialsException("Google UserInfo does not match ID token");
            }
            OAuthUserInfo userInfo = mapUserInfo(userInfoJson);
            userInfo.setEmailVerified(true); // From the validated ID token, not UserInfo.
            return userInfo;
        } catch (Exception e) {
            throw new BadCredentialsException("Failed to authenticate with Google", e);
        }
    }

    private Jwt verifyIdToken(String token, AuthProvider authProvider) {
        if (token == null || token.isBlank()) {
            throw new BadCredentialsException("Invalid Google ID token");
        }
        // Nimbus verifies the Google JWKS signature and standard token timestamps.
        Jwt idToken = idTokenDecoder.decode(token);
        String clientId = authProvider.getClientId();
        if (clientId == null || clientId.isBlank()
                || !idToken.getAudience().contains(clientId)
                || (!"https://accounts.google.com".equals(idToken.getClaimAsString("iss"))
                    && !"accounts.google.com".equals(idToken.getClaimAsString("iss")))
                || idToken.getExpiresAt() == null || !idToken.getExpiresAt().isAfter(Instant.now())
                || idToken.getSubject() == null || idToken.getSubject().isBlank()
                || idToken.getClaimAsString("email") == null || idToken.getClaimAsString("email").isBlank()
                || !Boolean.TRUE.equals(idToken.getClaimAsBoolean("email_verified"))
                || (idToken.hasClaim("azp") && !clientId.equals(idToken.getClaimAsString("azp")))) {
            throw new BadCredentialsException("Invalid Google identity");
        }
        return idToken;
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
