package com.mcueen.auth.service.oauth;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthUserInfo {
    private String providerId;
    private String email;
    private boolean emailVerified;
    private String firstName;
    private String lastName;
    private String name;
}
