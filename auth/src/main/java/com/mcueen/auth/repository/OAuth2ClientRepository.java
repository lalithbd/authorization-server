package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, Long> {

    OAuth2Client findByClientId(String clientId);
}
