package com.mcueen.auth.service.oauth;

import com.mcueen.auth.model.user.AuthProvider;

public interface OAuthProvider {

    /**
     * Validates an ID token presented by a client and returns the identity it asserts.
     * <p>
     * The token arrives from an untrusted caller, so implementations must verify it
     * cryptographically and confirm it was issued <em>to this application</em> — a token that is
     * merely valid at the provider may have been minted for someone else.
     *
     * @param authProvider provider configuration supplying the client id, issuer and JWKS URI the
     *                     token is checked against
     */
    com.mcueen.auth.service.oauth.OAuthUserInfo validateToken(String token, AuthProvider authProvider);

    com.mcueen.auth.service.oauth.OAuthUserInfo exchangeCodeAndGetUserInfo(String code, String redirectUri, AuthProvider authProvider);

    String getProviderName();
}
