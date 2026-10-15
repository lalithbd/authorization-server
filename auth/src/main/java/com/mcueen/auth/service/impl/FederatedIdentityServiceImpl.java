package com.mcueen.auth.service.impl;

import com.mcueen.auth.model.user.AuthProvider;
import com.mcueen.auth.model.user.User;
import com.mcueen.auth.repository.AuthProviderRepository;
import com.mcueen.auth.repository.UserRepository;
import com.mcueen.auth.service.FederatedIdentityService;
import com.mcueen.auth.service.oauth.OAuthUserInfo;
import com.mcueen.auth.util.auth.AuthConstants;
import com.mcueen.auth.util.auth.AuthErrorMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class FederatedIdentityServiceImpl implements FederatedIdentityService {

    private static final Logger log = LoggerFactory.getLogger(FederatedIdentityServiceImpl.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthProviderRepository authProviderRepository;

    @Override
    public AuthProvider requireEnabledProvider(String providerName) {
        return authProviderRepository.findByName(providerName)
                .filter(AuthProvider::isEnabled)
                .orElseThrow(() -> new BadCredentialsException(
                        AuthErrorMessages.UNSUPPORTED_PROVIDER + providerName));
    }

    @Override
    public User resolveUser(OAuthUserInfo oauthUser, String providerName) {
        if (!oauthUser.isEmailVerified()) {
            throw new BadCredentialsException(AuthErrorMessages.EMAIL_NOT_VERIFIED);
        }

        // The provider subject is the only stable identifier we have; an account keyed on a null
        // one would be shared by every future identity the provider fails to name.
        String providerId = oauthUser.getProviderId();
        if (providerId == null || providerId.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.MISSING_PROVIDER_IDENTITY);
        }

        String email = oauthUser.getEmail();
        if (email == null || email.isBlank()) {
            throw new BadCredentialsException(AuthErrorMessages.MISSING_PROVIDER_EMAIL);
        }

        Optional<User> linked = userRepository.findByOauthProviderAndOauthProviderId(providerName, providerId);
        if (linked.isPresent()) {
            return linked.get();
        }

        Optional<User> byEmail = userRepository.findByEmail(email);
        if (byEmail.isEmpty()) {
            return createOAuthUser(oauthUser, providerName);
        }

        User user = byEmail.get();
        if (user.getOauthProviderId() != null) {
            // The account already answers to a different provider identity. Matching only on email
            // here would sign the caller in as this user: the earlier lookup already proved the
            // presented identity is not the linked one, and the link below would be skipped, so
            // the takeover would also leave no trace on the account.
            log.warn("Rejected {} sign-in for an account already linked to provider {}",
                    providerName, user.getOauthProvider());
            throw new BadCredentialsException(AuthErrorMessages.ACCOUNT_ALREADY_LINKED);
        }

        // A password-only account claiming the same verified address adopts this provider as its
        // first link, which is the existing behaviour for AUTH_METHOD_BOTH.
        user.setOauthProvider(providerName);
        user.setOauthProviderId(providerId);
        user.setAuthMethod(AuthConstants.AUTH_METHOD_BOTH);
        return userRepository.save(user);
    }

    private User createOAuthUser(OAuthUserInfo oauthUser, String providerName) {
        User user = new User();
        user.setEmail(oauthUser.getEmail());
        user.setOauthProvider(providerName);
        user.setOauthProviderId(oauthUser.getProviderId());
        user.setFirstname(oauthUser.getFirstName());
        user.setLastname(oauthUser.getLastName());
        user.setAuthMethod(AuthConstants.AUTH_METHOD_OAUTH);
        return userRepository.save(user);
    }
}
