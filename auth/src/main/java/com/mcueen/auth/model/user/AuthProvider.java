package com.mcueen.auth.model.user;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(name = "auth_provider")
public class AuthProvider {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false)
    private String tokenEndpointUrl;

    @Column(nullable = false)
    private String userInfoUrl;

    private String clientId;

    private String clientSecret;

    @Column(nullable = false)
    private String authorizationUrl;

    @Column(nullable = false)
    private String scope;

    private String issuer;

    private String jwksUri;

    @Column(nullable = false)
    private boolean enabled = true;
}
