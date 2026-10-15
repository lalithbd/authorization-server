package com.mcueen.auth.service.oauth;

import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verifies an OIDC ID token against the issuing provider's JWKS.
 * <p>
 * Asking the provider "is this token valid?" is not enough: a token minted for some other
 * application is valid at the provider but was never intended for us. Presenting one here would
 * otherwise log the attacker in as that user. So every token is checked for
 * <ul>
 *   <li>a signature from the provider's published keys,</li>
 *   <li>{@code exp}/{@code nbf} within tolerance,</li>
 *   <li>{@code iss} among the issuers configured for the provider, and</li>
 *   <li>{@code aud} containing our own client id — the check that actually binds the token
 *       to this application.</li>
 * </ul>
 * Anything missing from configuration is treated as a configuration fault rather than being
 * skipped, so a half-configured provider fails closed.
 */
@Component
public class IdTokenVerifier {

    /**
     * A decoder holds a cached, periodically refreshed copy of the provider's JWKS, so one is
     * kept per provider configuration rather than rebuilt per request.
     */
    private final Map<String, JwtDecoder> decoders = new ConcurrentHashMap<>();

    /**
     * @param authProvider   provider configuration; {@code clientId} is required, while
     *                       {@code issuer} and {@code jwksUri} fall back to the arguments below
     *                       when blank
     * @param defaultIssuers accepted issuers when the provider row does not set one. An entry may
     *                       contain {@code {tenantid}}, which is replaced with the token's own
     *                       {@code tid} claim before comparison — the form Microsoft documents for
     *                       multi-tenant applications
     * @param defaultJwksUri JWKS location when the provider row does not set one
     * @throws BadCredentialsException if the token is missing, malformed, or fails any check
     * @throws IllegalStateException   if the provider is configured such that a check cannot run
     */
    public Jwt verify(String idToken, AuthProvider authProvider, Set<String> defaultIssuers, String defaultJwksUri) {
        if (idToken == null || idToken.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_ID_TOKEN);
        }

        String clientId = authProvider.getClientId();
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalStateException("auth_provider." + authProvider.getName()
                    + " has no client_id; the ID token audience cannot be verified without it");
        }

        String jwksUri = valueOrDefault(authProvider.getJwksUri(), defaultJwksUri);
        Set<String> issuers = issuers(authProvider, defaultIssuers);
        if (jwksUri == null || jwksUri.isBlank() || issuers.isEmpty()) {
            throw new IllegalStateException("auth_provider." + authProvider.getName()
                    + " needs both jwks_uri and issuer to verify ID tokens");
        }

        JwtDecoder decoder = decoders.computeIfAbsent(
                authProvider.getName() + '|' + jwksUri + '|' + clientId + '|' + issuers,
                key -> build(jwksUri, clientId, issuers));

        try {
            return decoder.decode(idToken);
        } catch (JwtException e) {
            // The reason is deliberately not echoed back to the caller; it is available in logs.
            throw new BadCredentialsException(AuthErrorMessages.INVALID_ID_TOKEN);
        }
    }

    private JwtDecoder build(String jwksUri, String clientId, Set<String> issuers) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        validators.add(issuerValidator(issuers));
        validators.add(audienceValidator(clientId));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
        return decoder;
    }

    private OAuth2TokenValidator<Jwt> issuerValidator(Set<String> accepted) {
        return jwt -> {
            String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
            String tenantId = jwt.getClaimAsString("tid");
            for (String candidate : accepted) {
                String expected = tenantId == null
                        ? candidate
                        : candidate.replace("{tenantid}", tenantId);
                if (expected.equals(issuer)) {
                    return OAuth2TokenValidatorResult.success();
                }
            }
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Unexpected ID token issuer: " + issuer, null));
        };
    }

    /**
     * The check that stops a token minted for another application from being accepted here.
     */
    private OAuth2TokenValidator<Jwt> audienceValidator(String clientId) {
        return jwt -> jwt.getAudience() != null && jwt.getAudience().contains(clientId)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
                        "ID token was not issued for this application", null));
    }

    private Set<String> issuers(AuthProvider authProvider, Set<String> defaults) {
        String configured = authProvider.getIssuer();
        if (configured == null || configured.isBlank()) {
            return defaults == null ? Set.of() : defaults;
        }
        // A provider may legitimately have more than one issuer spelling; accept a comma list.
        return Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }

    private String valueOrDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
