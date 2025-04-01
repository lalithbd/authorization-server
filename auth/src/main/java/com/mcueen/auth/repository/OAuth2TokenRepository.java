package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.OAuth2TokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OAuth2TokenRepository extends JpaRepository<OAuth2TokenEntity, Long> {

    void deleteAllByEmail(String name);

    void deleteAllByClientIdAndEmailIsNull(String name);

    List<OAuth2TokenEntity> findAllByAuthorizationId(String id);

    @Query("SELECT t FROM OAuth2TokenEntity t WHERE t.tokenValue = :token AND t.oAuth2TokenType = :oAuth2TokenType")
    OAuth2TokenEntity findByTokenValueAndoAuth2TokenType(@Param("token") String token, @Param("oAuth2TokenType") String oAuth2TokenType);
}
