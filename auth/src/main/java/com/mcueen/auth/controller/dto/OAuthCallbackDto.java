package com.mcueen.auth.controller.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthCallbackDto {

    private String code;
    private String provider;
    private String redirectUri;
}
