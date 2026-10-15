package com.mcueen.auth.config.security.filter;

import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Single place where client credentials are read off a request and verified, so every endpoint
 * that accepts them applies the same rules.
 */
@Component
public class ClientAuthenticator {

    @Autowired
    @Lazy
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Reads client credentials from the request and verifies them. Supports client_secret_basic
     * (Authorization header) and client_secret_post (form parameters).
     *
     * @throws BadCredentialsException if credentials are absent, malformed, or do not match
     */
    public RegisteredClient authenticate(HttpServletRequest request) {
        String header = request.getHeader(AuthConstants.AUTHORIZATION_HEADER);
        if (header != null && header.regionMatches(true, 0, AuthConstants.BASIC_PREFIX, 0, AuthConstants.BASIC_PREFIX_LENGTH)) {
            String decoded;
            try {
                decoded = new String(Base64.getDecoder().decode(header.substring(AuthConstants.BASIC_PREFIX_LENGTH).trim()),
                        StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
            }
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
            }
            return authenticate(decoded.substring(0, separator), decoded.substring(separator + 1));
        }
        return authenticate(request.getParameter(AuthConstants.FIELD_CLIENT_ID),
                request.getParameter(AuthConstants.FIELD_CLIENT_SECRET));
    }

    /**
     * Resolves a client from its id <em>without</em> verifying any secret.
     * <p>
     * This is identification, not authentication: a client id is public and proves nothing about
     * the caller. Use it only where the caller is a public client that cannot hold a secret, and
     * only to bind a request to a client — never as the sole gate on a credential-bearing flow.
     *
     * @throws BadCredentialsException if the client id is absent or unknown
     */
    public RegisteredClient identifyClient(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        return client;
    }

    /**
     * @throws BadCredentialsException if the client is unknown or the secret does not match
     */
    public RegisteredClient authenticate(String clientId, String clientSecret) {
        if (clientId == null || clientId.isBlank() || clientSecret == null || clientSecret.isEmpty()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
        }
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        if (client == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT);
        }
        if (client.getClientSecret() == null || !passwordEncoder.matches(clientSecret, client.getClientSecret())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_CLIENT_CREDENTIALS);
        }
        return client;
    }
}
