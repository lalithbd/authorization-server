package com.mcueen.auth.config.security.model;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@Service
public class CustomClientDetailsService implements ClientDetailsService {

    @Autowired
    private JpaRegisteredClientRepository registeredClientRepository;

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException("Client not found: " + clientId);
        }

        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(registeredClient.getClientId());
        clientDetails.setClientSecret(registeredClient.getClientSecret());
        clientDetails.setScope(registeredClient.getScopes());
        clientDetails.setAuthorizedGrantTypes(registeredClient.getAuthorizationGrantTypes()
                .stream().map(AuthorizationGrantType::getValue).toList());

        return clientDetails;
    }
}
