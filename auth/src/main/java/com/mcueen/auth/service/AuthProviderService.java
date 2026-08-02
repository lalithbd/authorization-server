package com.mcueen.auth.service;

import com.mcueen.auth.controller.dto.AuthProviderDto;
import com.mcueen.auth.controller.dto.OAuthCallbackDto;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.util.List;

public interface AuthProviderService {

    List<AuthProviderDto> getEnabledProviders();

    OAuth2AccessTokenResponse handleOAuthCallback(OAuthCallbackDto callbackDto, String clientId, String clientSecret);
}
