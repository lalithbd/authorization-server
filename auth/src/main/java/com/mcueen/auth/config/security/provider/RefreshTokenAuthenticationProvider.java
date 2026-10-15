package com.mcueen.auth.config.security.provider;

import com.mcueen.auth.config.security.model.ClientUserAuthenticationToken;
import com.mcueen.auth.config.security.model.RefreshTokenAuthenticationToken;
import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.service.impl.OAuth2AuthorizationServiceImpl;
import com.mcueen.auth.util.TokenType;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import com.mcueen.auth.util.auth.AuthGrantTypes;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Slf4j
@Component
public class RefreshTokenAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    @Lazy
    private RegisteredClientRepository registeredClientRepository;

    // The impl type, not the interface: rotation needs revokeToken, which is not part of the
    // OAuth2AuthorizationService contract.
    @Autowired
    private OAuth2AuthorizationServiceImpl auth2AuthorizationService;

    @Autowired
    private AuthenticationProviderHelper authenticationProviderHelper;

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

    }

    /**
     * How long after rotation the superseded token is still accepted, returning the replacement
     * pair instead of tripping reuse detection. Covers the client that rotated successfully but
     * never received the response — a dropped connection or a backgrounded mobile app — which is
     * indistinguishable on the wire from a replay. Set to zero to disable and treat every
     * re-presentation as reuse.
     */
    @Value("${auth.refresh-token.rotation-grace-seconds:15}")
    private long rotationGraceSeconds;

    /**
     * Ceiling on how long one login may be extended by rotation, regardless of how many times it
     * rotates. Reuse detection only fires when the legitimate client comes back; if it never does,
     * nothing else bounds a stolen token's life.
     */
    @Value("${auth.refresh-token.absolute-lifetime-seconds:2592000}")
    private long absoluteLifetimeSeconds;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RefreshTokenAuthenticationToken refreshTokenAuthentication = (RefreshTokenAuthenticationToken) authentication;
        String presentedToken = refreshTokenAuthentication.getRefreshToken();
        if (presentedToken == null || presentedToken.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_REFRESH_TOKEN);
        }

        // Read the row directly rather than through findByToken, which hides revoked tokens. A
        // revoked row is exactly what reuse detection needs to see.
        OAuth2TokenEntity tokenEntity = auth2AuthorizationService.findEntityByToken(presentedToken, TokenType.REFRESH);
        if (tokenEntity == null) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_REFRESH_TOKEN);
        }

        RegisteredClient client = registeredClientRepository.findById(tokenEntity.getClientId());
        if (client == null || !client.getAuthorizationGrantTypes().contains(AuthGrantTypes.REFRESH_TOKEN)) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_REFRESH_TOKEN);
        }

        // The client the caller presented must be the one the token was issued to, so client A
        // cannot refresh client B's token. The filter identified it from client_id alone, so this
        // binds the request to a client without proving who the caller is (RFC 6749 section 3.2.1).
        // Checked before the revoked branch so a wrong client cannot destroy another's session.
        RegisteredClient presentedClient = refreshTokenAuthentication.getRegisteredClient();
        if (presentedClient == null || !presentedClient.getClientId().equals(client.getClientId())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_REFRESH_TOKEN);
        }

        if (tokenEntity.isRevoked()) {
            return handleRevokedToken(tokenEntity, client);
        }

        if (isExpired(tokenEntity.getExpiresAt())) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_REFRESH_TOKEN);
        }

        // Rotation resets expiresAt every time, so only the family's original login date can stop a
        // session being extended indefinitely by an attacker who keeps refreshing.
        Instant grantIssuedAt = tokenEntity.getGrantIssuedAt();
        if (grantIssuedAt != null && absoluteLifetimeSeconds > 0
                && grantIssuedAt.plusSeconds(absoluteLifetimeSeconds).isBefore(Instant.now())) {
            log.info("Refresh refused: family {} passed its absolute lifetime", tokenEntity.getFamilyId());
            auth2AuthorizationService.revokeFamily(tokenEntity.getFamilyId());
            throw new BadCredentialsException(AuthErrorMessages.REFRESH_TOKEN_LIFETIME_EXCEEDED);
        }

        // The principal has to be carried over from the stored token. Passing the
        // RefreshTokenAuthenticationToken instead meant getName() resolved to "", and the refreshed
        // token was persisted with an empty email — losing the user's identity and every role with it.
        String principalName = tokenEntity.getEmail();
        if (principalName == null || principalName.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.INVALID_REFRESH_TOKEN);
        }

        OAuth2Authorization refreshed = authenticationProviderHelper.getOAuth2Authorization(
                new ClientUserAuthenticationToken(principalName), client, AuthGrantTypes.REFRESH_TOKEN,
                tokenEntity.getFamilyId(), grantIssuedAt);

        // Rotate: the presented token is retired now that its replacement exists, so it cannot be
        // replayed until natural expiry (RFC 9700 section 4.14). Recording the replacement lets a
        // client that lost the response retry within the grace window.
        auth2AuthorizationService.rotateToken(presentedToken, refreshed.getId());

        return new ClientUserAuthenticationToken(
                principalName, client, refreshed.getAccessToken(), refreshed.getRefreshToken());
    }

    /**
     * An already-rotated token was presented. Either the client never saw the response and is
     * retrying, or the token was stolen. Inside the grace window we assume the retry and hand back
     * the same pair; outside it we assume theft and retire the whole family.
     */
    private Authentication handleRevokedToken(OAuth2TokenEntity tokenEntity, RegisteredClient client) {
        Instant revokedAt = tokenEntity.getRevokedAt();
        String replacementId = tokenEntity.getReplacedByAuthorizationId();
        boolean withinGrace = revokedAt != null && rotationGraceSeconds > 0
                && revokedAt.plusSeconds(rotationGraceSeconds).isAfter(Instant.now());

        if (withinGrace && replacementId != null) {
            Authentication replay = replayReplacement(replacementId, tokenEntity, client);
            if (replay != null) {
                // Logged because a rising rate here is itself a signal: either a flaky client or an
                // attacker probing just inside the window.
                log.info("Replayed rotation response within grace window for family {}", tokenEntity.getFamilyId());
                return replay;
            }
        }

        // Two parties hold the same token and the server cannot tell which is legitimate, so it
        // ends both (RFC 9700 section 4.14.2). Access tokens go too — they are REFERENCE format,
        // so revoking them cuts the attacker off now rather than at expiry.
        int revoked = auth2AuthorizationService.revokeFamily(tokenEntity.getFamilyId());
        log.warn("Refresh token reuse detected for client {}; revoked {} token(s) in family {}",
                client.getClientId(), revoked, tokenEntity.getFamilyId());
        throw new BadCredentialsException(AuthErrorMessages.REFRESH_TOKEN_REUSED);
    }

    /**
     * Rebuilds the token pair a previous rotation issued. Returns null when the replacement is gone
     * or already revoked, which sends the caller down the reuse path.
     */
    private Authentication replayReplacement(String replacementAuthorizationId, OAuth2TokenEntity presented,
                                             RegisteredClient client) {
        OAuth2TokenEntity access = null;
        OAuth2TokenEntity refresh = null;
        for (OAuth2TokenEntity candidate : auth2AuthorizationService.findByAuthorizationId(replacementAuthorizationId)) {
            if (candidate.isRevoked()) {
                // The replacement was itself rotated or revoked; replaying it would hand back a
                // dead token, so fall through to reuse handling.
                return null;
            }
            if (TokenType.ACCESS.toString().equals(candidate.getTokenType())) {
                access = candidate;
            } else if (TokenType.REFRESH.toString().equals(candidate.getTokenType())) {
                refresh = candidate;
            }
        }
        if (access == null || refresh == null || isExpired(access.getExpiresAt())) {
            return null;
        }

        ClientUserAuthenticationToken replay = new ClientUserAuthenticationToken(presented.getEmail());
        replay.setRegisteredClient(client);
        replay.setAccessToken(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, access.getTokenValue(),
                access.getIssuedAt(), access.getExpiresAt(), access.getScopes()));
        replay.setRefreshToken(new OAuth2RefreshToken(refresh.getTokenValue(), refresh.getIssuedAt(),
                refresh.getExpiresAt()));
        return replay;
    }

    private boolean isExpired(Instant expiresAt) {
        return expiresAt == null || expiresAt.isBefore(Instant.now());
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
