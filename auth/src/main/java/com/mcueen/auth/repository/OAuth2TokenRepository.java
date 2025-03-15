package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2TokenRepository extends JpaRepository<OAuth2TokenEntity, Long> {

    Optional<OAuth2TokenEntity> findByTokenValue(String tokenValue);
}
