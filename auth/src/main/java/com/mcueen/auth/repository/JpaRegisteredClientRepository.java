package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.OAuth2Client;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2ClientRepository clientRepository;

    public JpaRegisteredClientRepository(OAuth2ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @Override
    public RegisteredClient findById(String id) {
        OAuth2Client oauth2Client = clientRepository.findById(Long.valueOf(id)).orElseThrow();
        return toRegisteredClient(oauth2Client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        OAuth2Client oauth2Client = clientRepository.findByClientId(clientId);
        return toRegisteredClient(oauth2Client);
    }

    private RegisteredClient toRegisteredClient(OAuth2Client oauth2Client) {
        List<AuthorizationGrantType> authorizationGrantTypeList = new ArrayList<>();
        oauth2Client.getGrantTypes().forEach(e -> authorizationGrantTypeList.add(new AuthorizationGrantType(e)));
        return RegisteredClient.withId(String.valueOf(oauth2Client.getId()))
                .clientId(oauth2Client.getClientId())
                .clientSecret(oauth2Client.getClientSecret())
                .redirectUris(uris -> uris.addAll(oauth2Client.getRedirectUris()))
                .scopes(scopes -> scopes.addAll(oauth2Client.getScopes()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantTypes(authorizationGrantTypes -> authorizationGrantTypes.addAll(authorizationGrantTypeList))
                .build();
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        OAuth2Client client = new OAuth2Client();
        client.setId(Long.valueOf(registeredClient.getId()));
        client.setClientId(registeredClient.getClientId());
        client.setClientSecret(registeredClient.getClientSecret());
        client.setRedirectUris(registeredClient.getRedirectUris());
        client.setScopes(registeredClient.getScopes());
        clientRepository.save(client);
    }
}
