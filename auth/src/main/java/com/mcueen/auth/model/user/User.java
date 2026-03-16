package com.mcueen.auth.model.user;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Entity
@Getter
@Setter
@Table(name = "userTable")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstname;
    private String lastname;
    private String email;
    private String password;
    
    @Column(name = "oauth_provider")
    private String oauthProvider; // "google", "microsoft", "facebook", etc.
    
    @Column(name = "oauth_provider_id")
    private String oauthProviderId; // Provider's user ID
    
    @Column(name = "auth_method")
    private String authMethod; // "EMAIL", "OAUTH", "BOTH"

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonManagedReference
    private List<UserRole> userRoles;


}
