package com.example.securitycourse.repository;

import com.example.securitycourse.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<AppUser, UUID> {
    Optional<AppUser> findByUsernameIgnoreCase(String username);

    Optional<AppUser> findByEmailIgnoreCase(String email);

    default Optional<AppUser> findByUsernameOrEmailIgnoreCase(String login) {
        Optional<AppUser> byUsername = findByUsernameIgnoreCase(login);
        if (byUsername.isPresent()) {
            return byUsername;
        }
        return findByEmailIgnoreCase(login);
    }

    boolean existsByUsernameIgnoreCase(String username);

    boolean existsByEmailIgnoreCase(String email);
}
