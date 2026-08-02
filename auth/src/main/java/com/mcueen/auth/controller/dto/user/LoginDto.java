package com.mcueen.auth.controller.dto.user;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginDto {

    private String provider; // "email", "google", "microsoft", "facebook", etc.
    private String email;
    private String password; // For email provider
    private String token; // For OAuth providers (ID token or access token)
}
