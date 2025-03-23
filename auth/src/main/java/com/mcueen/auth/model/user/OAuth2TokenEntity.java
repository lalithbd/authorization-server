package com.mcueen.auth.model.user;

import com.mcueen.auth.util.TokenType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

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

    @Enumerated(value = EnumType.STRING)
    private TokenType tokenType;
    private String clientId;
    private String tokenValue;
    private String email;
    private Instant issuedAt;
    private Instant expiresAt;
    private boolean isRevoked;

    @Column(columnDefinition = "json")
    private List<String> scopes;
}
