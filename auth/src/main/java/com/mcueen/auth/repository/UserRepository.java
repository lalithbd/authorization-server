package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    @Query("SELECT u FROM User u where u.email = :username")
    Optional<User> findByEmail(@Param("username") String username);

    boolean existsByEmail(String email);
}
