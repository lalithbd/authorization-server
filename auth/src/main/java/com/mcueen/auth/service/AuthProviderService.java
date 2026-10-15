package com.mcueen.auth.service;

import com.mcueen.auth.controller.dto.AuthProviderDto;
import com.mcueen.auth.controller.dto.OAuthCallbackDto;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;

public interface AuthProviderService {

    List<AuthProviderDto> getEnabledProviders();

    /**
     * @param client the caller, already authenticated by the filter
     */
    OAuth2AccessTokenResponse handleOAuthCallback(OAuthCallbackDto callbackDto, RegisteredClient client);
}
