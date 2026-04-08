package com.mcueen.auth.repository;

import com.mcueen.auth.model.user.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuthProviderRepository extends JpaRepository<AuthProvider, Long> {

    List<AuthProvider> findByEnabledTrue();

    Optional<AuthProvider> findByName(String name);
}
