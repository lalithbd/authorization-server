package com.mcueen.auth.service.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class OAuthProviderFactory {

    private final Map<String, OAuthProvider> providers;

    @Autowired
    public OAuthProviderFactory(List<OAuthProvider> providerList) {
        this.providers = providerList.stream()
            .collect(Collectors.toMap(
                OAuthProvider::getProviderName,
                Function.identity()
            ));
    }

    public OAuthProvider getProvider(String providerName) {
        OAuthProvider provider = providers.get(providerName.toLowerCase());
        if (provider == null) {
            throw new IllegalArgumentException("Unsupported OAuth provider: " + providerName);
        }
        return provider;
    }
}
