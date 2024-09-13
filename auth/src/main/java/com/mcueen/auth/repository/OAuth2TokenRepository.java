package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.OAuth2Token;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2TokenRepository extends JpaRepository<OAuth2Token, Long> {
}
