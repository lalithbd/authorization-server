package com.mcueen.auth.model.user;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Entity
@Data
@Builder
@Table(name = "OAuth2Token")
public class OAuth2TokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String tokenType;
    private String clientId;
    private String tokenValue;
    private String email;
    private Instant issuedAt;
    private Instant expiresAt;
}
