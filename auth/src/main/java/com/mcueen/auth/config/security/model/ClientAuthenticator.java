package com.mcueen.auth.config.security.model;

import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ClientAuthenticator {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    public ClientAuthenticator(RegisteredClientRepository registeredClientRepository, PasswordEncoder passwordEncoder) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public RegisteredClient getClient(String clientId) {
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        return client;
    }

    public RegisteredClient authenticateClient(HttpServletRequest request) {
        String authHeader = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);
        if (authHeader == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CREDENTIALS);
        }
        String base64Credentials = authHeader.substring(AuthConstants.BASIC_PREFIX_LENGTH);
        String credentials = new String(Base64.getDecoder().decode(base64Credentials), StandardCharsets.UTF_8);
        String[] parts = credentials.split(":", 2);
        return authenticateClient(parts[0], parts[1]);
    }

    private RegisteredClient authenticateClient(String clientId, String clientSecret) {
        if (clientId == null || clientId.isBlank() || clientSecret == null || clientSecret.isEmpty()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
        }
        RegisteredClient client = getClient(clientId);
        if (client.getClientSecret() == null || !passwordEncoder.matches(clientSecret, client.getClientSecret())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
        }
        return client;

    }
}
