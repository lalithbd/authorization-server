package com.mcueen.auth.service;

import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.service.oauth.OAuthUserInfo;

/**
 * Maps a verified provider identity onto a local user account.
 * <p>
 * The login filter and the OAuth callback both need this, and they previously each carried their
 * own copy of it — which is why the same account-linking flaw existed twice.
 */
public interface FederatedIdentityService {

    /**
     * @throws org.springframework.security.authentication.BadCredentialsException
     *         if the provider is unknown or disabled
     */
    AuthProvider requireEnabledProvider(String providerName);

    /**
     * Resolves the account for an already-verified provider identity, creating one on first
     * sign-in and linking one that has no provider yet.
     *
     * @throws org.springframework.security.authentication.BadCredentialsException
     *         if the email is unverified or absent, the provider subject is absent, or the email
     *         belongs to an account already linked to a different provider identity
     */
    User resolveUser(OAuthUserInfo oauthUser, String providerName);
}
