package com.mcueen.auth.config.security.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UnAuthorizedResponse {

    private String status;
    private String message;
}
