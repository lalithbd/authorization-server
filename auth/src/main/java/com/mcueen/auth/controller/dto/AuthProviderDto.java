package com.mcueen.auth.controller.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AuthProviderDto {

    private Long id;
    private String name;
    private String authorizationUrl;
    private String clientId;
    private String scope;
}
