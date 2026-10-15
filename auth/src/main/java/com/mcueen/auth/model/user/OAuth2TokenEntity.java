package com.mcueen.auth.model.user;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Set;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "OAuth2Token")
public class OAuth2TokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String authorizationId;
    private String clientId;
    private String tokenType;
    private String tokenValue;
    private String email;
    private Instant issuedAt;
    private Instant expiresAt;
    private boolean isRevoked;
    private Set<String> scopes;
    private String grantType;

    /**
     * Groups every token descended from one login. Rotation carries this value forward, so
     * presenting an already-rotated refresh token can retire the whole chain at once
     * (RFC 9700 section 4.14.2). Null on rows issued before rotation tracking existed.
     */
    private String familyId;

    /**
     * When the family's original login happened, carried unchanged through every rotation.
     * Rotation refreshes {@code issuedAt}, so only this value can bound how long a session may
     * be extended.
     */
    private Instant grantIssuedAt;

    /**
     * When this token was retired. Used to tell a genuine retry of a lost response from a replay.
     */
    private Instant revokedAt;

    /**
     * The authorization whose tokens replaced this one. Lets a client that never received the
     * rotation response retry and be handed the same pair again.
     */
    private String replacedByAuthorizationId;
}
