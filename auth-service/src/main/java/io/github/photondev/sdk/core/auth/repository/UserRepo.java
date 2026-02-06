package io.github.photondev.sdk.core.auth.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.github.photondev.sdk.core.auth.model.User;

public interface UserRepo extends JpaRepository<User, Long>{
    Optional<User> findByUsername(String username);
}
