package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import com.mcueen.auth.util.TokenType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OAuth2TokenRepository extends JpaRepository<OAuth2TokenEntity, Long> {

    Optional<OAuth2TokenEntity> findByTokenValueAndTokenType(String tokenValue, String value);

    void deleteAllByEmail(String name);

    void deleteAllByClientIdAndEmailIsNull(String name);

    List<OAuth2TokenEntity> findAllByAuthorizationId(String id);
}
